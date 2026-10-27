"""Incident building: per-user correlation of VPN + AD activity over
the last 24 hours, scored with fixed SOC rules.

v1.6.0 UEBA (v2)
================
v1.5.0 flagged every evening login, every typo-retry streak and every
structural AD-without-VPN pattern because the rules have no personal
context - a night-shift admin scored the same as an account thief.
This version moderates the SAME rules with per-user baselines:

* For each user the engine profiles (over min(UEBA_BASELINE_DAYS,
  RETENTION_DAYS) days, refreshed every UEBA_BASELINE_TTL_HOURS):
  typical UTC hours of successful logins, typical daily failed-login
  count, known countries, routine fast geo pairs (commute / mobile-ISP
  geo flips) and how often their AD authentications from public IPs
  legitimately lack a VPN session.
* A rule signal that matches the user's own history contributes 0:
  off-hours at personally typical hours, failed-logins within the
  personal norm, multi-geo across already-known countries, the exact
  fast country pair seen >= UEBA_PAIR_MIN times before, routine
  AD-without-VPN.
* Users younger than UEBA_MIN_DAYS active days get a PEER baseline
  (profile of established users only): off-hours and failed-logins can
  still be suppressed with peer evidence, geo and ad_uncov never.
* Absolutes are never suppressed: >= UEBA_ABS_BRUTE_FAILED failed
  logins in the LAST hour plus successful authentication in the window
  is a brute-force success - the score is floored to UEBA_ABS_FLOOR.

Storage: two new tables (user_baselines, org_baseline), created here on
first use - retention_job() never touches them, so profiles survive the
7-day event purge.

Rollback (v1.5.0 behaviour, scores and payload byte-identical):
  * env: UEBA_ENABLED=false (add to the api service environment: list
    in docker-compose.yml), or
  * DB, no rebuild needed:
    INSERT OR REPLACE INTO settings (key,value) VALUES ('ueba_enabled','false')
  Re-enable by removing the row / setting 'true'.

Everything is fail-open: on any baseline error (broken DB, failed
rebuild) the plain v1.5.0 rule scores are used.

Incident payload gains two fields when UEBA is active (harmless for the
frontend and the LLM triage, which read fixed keys):
  rule_score - raw v1.5.0 score before suppression
  ueba       - {"personal", "active_days", "suppressed": [...], "note": [...]}

v1.6.1 runtime settings
=======================
Every UEBA_* knob is layered: hardcoded defaults <- environment
(deployment level, needs a restart) <- settings table (keys
ueba_<name>, written by the Settings -> UEBA tab). The settings layer
lives in data/system.db, so UI tuning survives container rebuilds.
The live _UEBA dict is folded from the settings table once per build
cycle (refresh_ueba_config, fail-open). The tab's API endpoints live
in routes/system.py: GET/POST/DELETE /api/settings/ueba and
POST /api/settings/ueba/rebuild.
"""
import datetime
import ipaddress
import json
import logging
import os
import statistics
import threading
import time
from collections import Counter, defaultdict
from zoneinfo import ZoneInfo

from config import settings
from database import db
from geo import lookup as geo_lookup, get_timezone_for_ip

log = logging.getLogger("incidents")

UTC = datetime.timezone.utc
FMT = "%Y-%m-%d %H:%M:%S"


def _fmt(dt):
    return dt.strftime(FMT)


def _valid_user(u):
    return bool(u) and u not in ("N/A", "ERROR", "*****", "")


def _in_nets(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def _is_internal_ip(ip):
    """Corporate-internal address (office LAN, VPN pool, loopback).

    AD access from such an address never requires a VPN session -
    the user is already inside the perimeter.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback


def _parse_ts(ts):
    try:
        return datetime.datetime.strptime(ts, FMT).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def build_incidents(usernames=None):
    """Build incidents for the last 24h.

    usernames=None -> automatic mode: only users with
                     risk_score >= INCIDENT_MIN_SCORE are returned.
    usernames=set  -> explicit request (manual AI Triage):
                     threshold bypassed, asked users always returned.

    v1.6.0: rule scores are moderated by personal baselines (see the
    UEBA section at the bottom of this file) before the threshold is
    applied. Suppressed users simply score below the threshold and
    disappear from the automatic list; manual requests still show them
    (with rule_score and the ueba explanation in the payload).

    v1.6.2: incidents closed as false positives by an analyst (per
    user+day) drop out of the automatic list; watchlists (elevated /
    benign) and MITRE tags are attached while UEBA is active.
    """
    threshold = settings.incident_min_score if usernames is None else 0
    cutoff = _fmt(datetime.datetime.now(UTC) - datetime.timedelta(hours=24))
    hour_cut = _fmt(datetime.datetime.now(UTC) - datetime.timedelta(hours=1))
    with db() as conn:
        vpn_rows = [dict(r) for r in conn.execute(
            "SELECT DISTINCT timestamp,username,src_ip,private_ip FROM vpn_events "
            "WHERE action='login_success' AND src_ip != 'N/A' AND timestamp >= ?", (cutoff,))]
        ad_rows = [dict(r) for r in conn.execute(
            "SELECT DISTINCT timestamp,username,src_ip,hostname FROM ad_events "
            "WHERE action IN ('logon_success','kerberos_tgt') AND src_ip != 'N/A' AND timestamp >= ?", (cutoff,))]
        logout_rows = [dict(r) for r in conn.execute(
            "SELECT timestamp,username,private_ip FROM vpn_events WHERE action='logout' AND timestamp >= ?", (cutoff,))]
        failed = defaultdict(int)
        for table, act in (("vpn_events", "login_failed"), ("ad_events", "logon_failed")):
            for r in conn.execute(
                    f"SELECT username,SUM(COALESCE(event_count,1)) c FROM {table} WHERE action=? AND timestamp >= ? GROUP BY username",
                    (act, cutoff)):
                if _valid_user(r["username"]):
                    failed[r["username"]] += r["c"]
        failed_1h = defaultdict(int)
        for table, act in (("vpn_events", "login_failed"), ("ad_events", "logon_failed")):
            for r in conn.execute(
                    f"SELECT username,SUM(COALESCE(event_count,1)) c FROM {table} WHERE action=? AND timestamp >= ? GROUP BY username",
                    (act, hour_cut)):
                if _valid_user(r["username"]):
                    failed_1h[r["username"]] += r["c"]

    vpn_rows = [r for r in vpn_rows if _valid_user(r["username"])]
    ad_rows = [r for r in ad_rows if _valid_user(r["username"]) and not _in_nets(r["src_ip"], settings.excluded_ad_nets)]
    if usernames is not None:
        vpn_rows = [r for r in vpn_rows if r["username"] in usernames]
        ad_rows = [r for r in ad_rows if r["username"] in usernames]

    common = {r["username"] for r in vpn_rows} & {r["username"] for r in ad_rows}
    if not common:
        return []

    # v1.6.1: fold Settings -> UEBA overrides into the live config once
    # per cycle (fail-open, keeps previous values on any error)
    refresh_ueba_config()
    # effective switch (env AND settings-table), read once per build:
    # with UEBA off the payload must stay byte-identical to v1.5.0
    ueba_on = _ueba_enabled_db()
    baselines, org = _ensure_baselines() if ueba_on else ({}, None)
    watchlists, triage = ({}, {}) if not ueba_on else (_load_watchlists(), _load_triage())

    return _build_all(common, vpn_rows, ad_rows, logout_rows, failed, threshold,
                      failed_1h, baselines, org, ueba_on,
                      watchlists=watchlists, triage=triage,
                      exclude_fp=ueba_on and usernames is None)


def _build_all(common, vpn_rows, ad_rows, logout_rows, failed, min_score=0,
               failed_1h=None, baselines=None, org=None, ueba_on=False,
               watchlists=None, triage=None, exclude_fp=False):
    user_vpn = defaultdict(list)
    for r in vpn_rows:
        user_vpn[r["username"]].append((r["timestamp"], r["src_ip"], r.get("private_ip") or "N/A"))
    user_ad = defaultdict(list)
    for r in ad_rows:
        user_ad[r["username"]].append((r["timestamp"], r["src_ip"], r.get("hostname") or "-"))
    user_logout = defaultdict(list)
    for r in logout_rows:
        if _valid_user(r["username"]):
            user_logout[r["username"]].append((r["timestamp"], r.get("private_ip") or "N/A"))

    geo_map = geo_lookup({ip for u in common for _, ip, _ in user_vpn[u]})

    cached = _get_cached()
    failed_1h = failed_1h or {}
    baselines = baselines or {}
    watchlists = watchlists or {}
    triage = triage or {}

    incidents = []
    filtered_out = 0
    closed_fp = 0
    for user in common:
        inc = _build_one(user, user_vpn[user], user_ad[user],
                         user_logout[user], failed.get(user, 0),
                         geo_map, cached.get(user), min_score,
                         failed_1h.get(user, 0), baselines.get(user), org,
                         ueba_on, watchlists.get(user) or set())
        if inc:
            # v1.6.2: attach the analyst verdict for this exact user-day;
            # 'fp' drops out of the automatic list so it never re-alerts
            key = ((inc["username"], inc["last_seen"][:10])
                   if inc["last_seen"] != "N/A" else None)
            verdict = triage.get(key) if key else None
            if verdict:
                inc["triage"] = {"status": verdict["status"],
                                 "reason": verdict["reason"],
                                 "by": verdict["triaged_by"],
                                 "date": key[1]}
            if exclude_fp and verdict and verdict["status"] == "fp":
                closed_fp += 1
                continue
            incidents.append(inc)
        else:
            filtered_out += 1

    log.info("[INCIDENTS] %d built, %d below threshold (min_score=%d, ueba=%s)%s",
             len(incidents), filtered_out, min_score,
             "on" if _UEBA["enabled"] else "off",
             (", closed-fp=%d" % closed_fp) if exclude_fp else "")

    incidents.sort(key=lambda x: x["last_seen"], reverse=True)
    return incidents


def _get_cached():
    """Latest AI verdict per user within the cache window (1h)."""
    cache_cut = _fmt(datetime.datetime.now(UTC) - datetime.timedelta(hours=1))
    cached = {}
    with db() as conn:
        for r in conn.execute(
                "SELECT username,verdict,reason FROM incident_analysis "
                "WHERE created_at >= ? ORDER BY created_at DESC", (cache_cut,)):
            if r["username"] not in cached:
                cached[r["username"]] = (r["verdict"], r["reason"])
    return cached


def _build_one(user, u_vpn, u_ad, u_logout, failed_n, geo_map, cached, min_score=0,
               failed_1h=0, baseline=None, org=None, ueba_on=False, watchlists=None):
    default_tz = ZoneInfo(settings.timezone)

    sessions = _build_sessions(u_vpn, u_logout)
    ad_uncov = _check_ad_coverage(u_ad, sessions)
    off_hours, off_utc = _check_off_hours(u_vpn, u_ad, default_tz)
    multi_geo, geo_gap, countries, gap_pair = _check_geo(u_vpn, geo_map)
    min_diff = _calc_min_diff(u_vpn, u_ad)
    rule_score = _calc_score(multi_geo, geo_gap, off_hours, failed_n, ad_uncov)
    wl = watchlists or set()
    instant = _instant_signal(min_diff) if ueba_on else False
    score, ueba = _ueba_adjust(rule_score, off_hours, off_utc, multi_geo, geo_gap,
                               gap_pair, failed_n, failed_1h, ad_uncov,
                               countries, baseline, org,
                               instant=instant, watchlists=wl)

    # Below the incident threshold: not suspicious enough to be an
    # incident (clean users, office workers with only ad-no-vpn etc.)
    if score < min_score:
        return None

    severity = _calc_severity(score)
    details = _build_details(u_vpn, u_ad, geo_map)

    ai_v, ai_r = cached or ("not_analyzed", "N/A")

    times = [t for t, _, _ in u_vpn] + [t for t, _, _ in u_ad]

    inc = {
        "username": user,
        "vpn_count": len(u_vpn), "ad_count": len(u_ad),
        "min_diff": round(min_diff, 1) if min_diff is not None else None,
        "off_hours": off_hours, "multi_geo": multi_geo,
        "geo_gap_min": round(geo_gap, 1) if geo_gap is not None else None,
        "ad_without_vpn": ad_uncov,
        "failed_logins": failed_n,
        "risk_score": score, "severity": severity,
        "last_seen": max(times) if times else "N/A",
        "vpn_ips": (" | ".join(f"{ip} ({t})" for t, ip, _ in u_vpn))[:400] or "-",
        "ad_ips": (" | ".join(f"{ip} ({t})" for t, ip, _ in u_ad))[:400] or "-",
        "vpn_geo": (" | ".join(geo_map.get(ip, "N/A") for _, ip, _ in u_vpn))[:400] or "-",
        "ad_hosts": (" | ".join(h for _, _, h in u_ad))[:400] or "-",
        "details": details,
        "ai_verdict": ai_v, "ai_reason": ai_r
    }
    if ueba is not None and ueba_on:
        # only when UEBA is active: the v1.5.0 payload stays
        # byte-identical when the feature is disabled
        inc["rule_score"] = rule_score
        inc["ueba"] = ueba
    if ueba_on:
        # v1.6.2: MITRE tags for the rules that survived suppression
        raw = []
        if multi_geo:
            raw.append("impossible_travel" if (geo_gap is not None and geo_gap <= 120)
                       else "multi_geo")
        if off_hours:
            raw.append("off_hours")
        if failed_n >= settings.brute_force_threshold:
            raw.append("failed_logins")
        if ad_uncov:
            raw.append("ad_without_vpn")
        if instant:
            raw.append("instant_switch")
        if ueba and ueba.get("absolute"):
            raw.append("brute_force_success")
        supp = set(ueba["suppressed"]) if ueba else set()
        inc["mitre"] = _mitre_tags(s for s in raw if s not in supp)
        if wl:
            inc["watchlists"] = sorted(wl)
    return inc


def _build_sessions(u_vpn, u_logout):
    sessions = []
    for ts, _, priv in u_vpn:
        end = None
        for lts, lpriv in u_logout:
            if lts >= ts and lpriv == priv:
                end = lts if end is None else min(end, lts)
        sessions.append((ts, end, priv))
    return sessions


_AD_GRACE = datetime.timedelta(minutes=15)
_AD_COARSE = datetime.timedelta(hours=2)


def _ad_covered(tdt, sessions, vpn_times, now):
    """Is this AD event inside a VPN session window ([login-15m,
    logout+15m]) or within +-2h of any VPN login?"""
    for s, e, _ in sessions:
        sdt = _parse_ts(s)
        if not sdt:
            continue
        hi = (_parse_ts(e) or now) + _AD_GRACE
        if (sdt - _AD_GRACE) <= tdt <= hi:
            return True
    for v in vpn_times:
        if abs((tdt - v).total_seconds()) <= _AD_COARSE.total_seconds():
            return True
    return False


def _check_ad_coverage(u_ad, sessions):
    """True if any AD authentication cannot be explained by corporate
    network presence or an active VPN session.

    - AD src_ip internal (office LAN, VPN pool): normal - the user is
      already inside the perimeter, VPN is not required.
    - AD src_ip public: must fall inside a VPN session window
      ([login-15m, logout+15m], or within +-2h of any VPN login),
      otherwise flagged - that is perimeter bypass.
    """
    vpn_times = [t for t in (_parse_ts(s) for s, _, _ in sessions) if t]
    now = datetime.datetime.now(UTC)

    for ts, ip, _ in u_ad:
        if _is_internal_ip(ip):
            continue  # office / VPN internal address - no VPN required

        tdt = _parse_ts(ts)
        if not tdt:
            continue

        if not _ad_covered(tdt, sessions, vpn_times, now):
            return True
    return False


def _count_ad_uncovered(u_ad, sessions):
    """Uncovered-AD statistics for the baseline window: how many
    public-IP AD events had no covering VPN session. Users with a
    structural pattern (e.g. a mail app authenticating from a home
    public IP without VPN) collect a large count here, which later
    suppresses the +10 ad_uncov rule for them."""
    vpn_times = [t for t in (_parse_ts(s) for s, _, _ in sessions) if t]
    now = datetime.datetime.now(UTC)
    count = 0
    for ts, ip, _ in u_ad:
        if _is_internal_ip(ip):
            continue
        tdt = _parse_ts(ts)
        if not tdt:
            continue
        if not _ad_covered(tdt, sessions, vpn_times, now):
            count += 1
    return count


def _check_off_hours(u_vpn, u_ad, default_tz):
    """(off_hours, flagged_utc_hours): whether any event falls into the
    off-hours window in the user's local timezone, plus the UTC hours
    of the flagged events (UEBA checks them against personal/peer
    routines; UTC is used because that is how the DB stores time)."""
    times = [t for t, _, _ in u_vpn] + [t for t, _, _ in u_ad]

    # Try to get user timezone from first VPN IP
    user_tz = default_tz
    for _, ip, _ in u_vpn:
        tz_name = get_timezone_for_ip(ip)
        if tz_name:
            try:
                user_tz = ZoneInfo(tz_name)
                break
            except Exception:
                pass

    off = False
    flagged = []
    for t in times:
        dt = _parse_ts(t)
        if not dt:
            continue
        lh = dt.astimezone(user_tz).hour
        if lh >= settings.off_hours_start or lh < settings.off_hours_end:
            off = True
            flagged.append(dt.hour)
    return off, flagged


def _check_geo(u_vpn, geo_map):
    """(multi_geo, geo_gap, countries, gap_pair): more than one country
    in the window, the minimum country-switch gap in minutes, the set
    of countries seen, and the ordered pair that produced that gap."""
    entries = sorted((t, geo_map.get(ip, "N/A")) for t, ip, _ in u_vpn)
    countries = [(t, g.split(",")[0].strip() if g not in ("N/A", "Internal") else g) for t, g in entries]

    geo_gap = None
    gap_pair = None
    for i in range(1, len(countries)):
        c0, c1 = countries[i - 1][1], countries[i][1]
        if c0 != c1 and "N/A" not in (c0, c1) and "Internal" not in (c0, c1):
            t0, t1 = _parse_ts(countries[i - 1][0]), _parse_ts(countries[i][0])
            if t0 and t1:
                d = (t1 - t0).total_seconds() / 60
                if geo_gap is None or d < geo_gap:
                    geo_gap, gap_pair = d, (c0, c1)

    uniq = {c for _, c in countries if c not in ("N/A", "Internal")}
    multi_geo = len(uniq) > 1
    return multi_geo, geo_gap, uniq, gap_pair


def _calc_min_diff(u_vpn, u_ad):
    min_diff = None
    for vt, _, _ in u_vpn:
        vdt = _parse_ts(vt)
        if not vdt:
            continue
        for at, _, _ in u_ad:
            adt = _parse_ts(at)
            if adt:
                d = abs((vdt - adt).total_seconds()) / 60
                min_diff = d if min_diff is None else min(min_diff, d)
    return min_diff


def _calc_score(multi_geo, geo_gap, off_hours, failed, ad_uncov):
    score = 0
    if multi_geo:
        score += 35
    if geo_gap is not None and geo_gap <= 120:
        score += 25
    if off_hours:
        score += 20
    if failed >= settings.brute_force_threshold:
        score += 15
    if ad_uncov:
        score += 10
    return min(score, 100)


def _calc_severity(score):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


# v1.6.2: MITRE ATT&CK labels per triggered rule. Tagged are only the
# rules that actually contribute to the final score - suppressed rules
# are part of the user's routine and are deliberately not tagged.
_MITRE_RULES = {
    "multi_geo": ("T1078 Valid Accounts",),
    "impossible_travel": ("T1078 Valid Accounts",),
    "off_hours": ("T1078 Valid Accounts",),
    "failed_logins": ("T1110 Brute Force",),
    "brute_force_success": ("T1110 Brute Force",),
    "ad_without_vpn": ("T1021 Remote Services",),
    "instant_switch": ("T1078 Valid Accounts",),
}


def _mitre_tags(signals):
    """Deduplicated MITRE ATT&CK labels for the given rule names."""
    seen, out = set(), []
    for s in signals:
        for tag in _MITRE_RULES.get(s, ()):
            if tag not in seen:
                seen.add(tag)
                out.append(tag)
    return out


def _instant_signal(min_diff):
    """True when the VPN login and the first AD activity follow each
    other faster than any human would plausibly type credentials - a
    scripted-access pattern (automation on a possibly stolen session).
    Supporting signal only: it never fires on its own, it just amplifies
    other triggered rules (off-hours / geo / failures) by +10."""
    return min_diff is not None and min_diff <= _UEBA["instant_min_diff"]


def _build_details(u_vpn, u_ad, geo_map):
    details = [{"time": t, "source": "VPN", "ip": ip,
                "geo": geo_map.get(ip, "N/A"), "host": priv} for t, ip, priv in u_vpn]
    details += [{"time": t, "source": "AD", "ip": ip, "geo": "-", "host": host} for t, ip, host in u_ad]
    details.sort(key=lambda x: x["time"], reverse=True)
    return details


# ---------------------------------------------------------------------------
# UEBA v1.6.0: personal baselines that suppress rule points for known
# user routines. All knobs are optional env vars with sane defaults.
# Kill-switch: UEBA_ENABLED=false (env) or the settings-table key
# 'ueba_enabled'='false' (no rebuild needed). Fail-open everywhere.
# v1.6.2: watchlists (elevated/benign), analyst triage (tp/fp per
# user-day), MITRE tags and the instant VPN->AD supporting signal.
# ---------------------------------------------------------------------------

def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name, default):
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


_UEBA_SPEC = {
    # setting key: (kind, min, max) - shared by validation and the API
    "min_days": ("int", 1, 30),
    "hour_min_occ": ("int", 1, 24),
    "org_hour_min_users": ("int", 1, 100),
    "fail_mult": ("float", 1.0, 10.0),
    "fail_margin": ("float", 0.0, 100.0),
    "ad_uncov_min": ("int", 1, 100),
    "pair_min": ("int", 1, 100),
    "abs_brute_failed": ("int", 2, 1000),
    "abs_floor": ("int", 20, 100),
    "baseline_days": ("int", 1, 90),
    "ttl_hours": ("int", 1, 168),
    "instant_min_diff": ("float", 0.0, 60.0),
}


def _env_defaults():
    """Bottom config layer: hardcoded defaults overridable via UEBA_*
    environment variables (deployment level, needs a container restart)."""
    return {
        # master switch (env); the settings-table key overrides at runtime
        "enabled": os.getenv("UEBA_ENABLED", "true").strip().lower() == "true",
        # min distinct active days for a personal (vs peer) baseline
        "min_days": _env_int("UEBA_MIN_DAYS", 3),
        # personal: min occurrences of the hour (+-1h tolerance)
        "hour_min_occ": _env_int("UEBA_HOUR_MIN_OCC", 3),
        # peer fallback: min established users active at that hour
        "org_hour_min_users": _env_int("UEBA_ORG_HOUR_MIN_USERS", 3),
        # failed logins: suppressed when failed <= typical_daily*mult + margin
        "fail_mult": _env_float("UEBA_FAIL_MULT", 2.0),
        "fail_margin": _env_float("UEBA_FAIL_MARGIN", 3),
        # uncovered AD from a public IP: routine when seen >= this often
        "ad_uncov_min": _env_int("UEBA_AD_UNCOV_MIN", 5),
        # a fast country pair is routine when seen >= this many times
        "pair_min": _env_int("UEBA_PAIR_MIN", 3),
        # absolute: failed logins within the LAST hour + successful auth
        "abs_brute_failed": _env_int("UEBA_ABS_BRUTE_FAILED", 15),
        "abs_floor": _env_int("UEBA_ABS_FLOOR", 80),
        # baseline window (clamped to RETENTION_DAYS) and refresh interval
        "baseline_days": _env_int("UEBA_BASELINE_DAYS", 14),
        "ttl_hours": _env_int("UEBA_BASELINE_TTL_HOURS", 6),
        # instant VPN->AD handover: scripted-access threshold, minutes
        "instant_min_diff": _env_float("UEBA_INSTANT_MIN_DIFF", 2.0),
    }


# live configuration: folded from the settings table once per build
# cycle (see refresh_ueba_config); tests patch items on this exact dict
_UEBA = _env_defaults()


def _db_ueba_overrides():
    """Top config layer: knob overrides stored in the settings table
    (keys ueba_<name>, written by Settings -> UEBA). Broken or
    out-of-range stored values are ignored (fall back to env/defaults)."""
    out = {}
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT key,value FROM settings WHERE key LIKE 'ueba_%'").fetchall()
    except Exception:
        return out
    for r in rows:
        key = (r["key"] or "")[5:]
        if key not in _UEBA_SPEC:
            continue  # ueba_enabled and unknown keys are handled elsewhere
        try:
            kind, lo, hi = _UEBA_SPEC[key]
            val = float(r["value"])
            if kind == "int":
                val = int(round(val))
            if lo <= val <= hi:
                out[key] = val
        except (TypeError, ValueError):
            continue
    return out


def _db_ueba_enabled():
    """Runtime switch from the settings table: True/False, None = unset."""
    try:
        with db() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key='ueba_enabled'").fetchone()
        if row and str(row["value"]).strip().lower() in ("true", "false"):
            return str(row["value"]).strip().lower() == "true"
    except Exception:
        pass
    return None


def refresh_ueba_config():
    """Fold the settings-table layer into the live _UEBA dict (called
    once per build cycle; fail-open keeps the previous values on any
    error). Updated in place so existing readers and tests that patch
    items on _UEBA keep working."""
    try:
        cfg = _env_defaults()
        cfg.update(_db_ueba_overrides())
        # 'enabled' stays env-driven here: the runtime DB switch is
        # resolved per cycle by _ueba_enabled_db()
        cfg["enabled"] = _UEBA["enabled"]
        _UEBA.clear()
        _UEBA.update(cfg)
    except Exception:
        log.exception("[UEBA] config refresh failed (keeping previous)")


def effective_ueba_config():
    """The full effective configuration (env + settings layers) as
    returned by GET /api/settings/ueba. 'enabled' is the combined
    state; 'env_forced_off' marks the deployment-level hard switch."""
    cfg = _env_defaults()
    cfg.update(_db_ueba_overrides())
    env_on = _UEBA["enabled"]  # env layer (fixed for the process lifetime)
    db_on = _db_ueba_enabled()
    cfg["env_forced_off"] = not env_on
    cfg["enabled"] = env_on and db_on is not False
    return cfg


def validate_ueba_overrides(body):
    """Validate a partial override payload from the Settings UI.
    Returns (clean, errors): clean maps setting keys to typed values
    ('enabled' is a bool); errors is a list of readable rejections."""
    clean, errors = {}, []
    if not isinstance(body, dict):
        return clean, ["body must be a JSON object"]
    if "enabled" in body:
        v = body["enabled"]
        if isinstance(v, bool):
            clean["enabled"] = v
        elif str(v).strip().lower() in ("true", "false"):
            clean["enabled"] = str(v).strip().lower() == "true"
        else:
            errors.append("enabled: must be true or false")
    for key, raw in body.items():
        if key == "enabled":
            continue
        if key not in _UEBA_SPEC:
            errors.append(f"unknown setting: {key}")
            continue
        kind, lo, hi = _UEBA_SPEC[key]
        try:
            val = float(raw)
        except (TypeError, ValueError):
            errors.append(f"{key}: must be a number")
            continue
        if kind == "int" and abs(val - round(val)) > 1e-9:
            errors.append(f"{key}: must be an integer")
            continue
        if kind == "int":
            val = int(round(val))
        if not lo <= val <= hi:
            errors.append(f"{key}: must be between {lo} and {hi}")
            continue
        clean[key] = val
    return clean, errors


def ueba_status():
    """Snapshot for the Settings -> UEBA tab: effective config, active
    overrides and baseline health."""
    cfg = effective_ueba_config()
    overrides = _db_ueba_overrides()
    enabled = cfg.pop("enabled")
    env_forced_off = cfg.pop("env_forced_off")
    baselines = {"users": 0, "updated_at": ""}
    try:
        with db() as conn:
            _ensure_ueba_tables(conn)
            row = conn.execute("SELECT COUNT(*) AS c FROM user_baselines").fetchone()
            baselines["users"] = row["c"] if row else 0
            org = conn.execute(
                "SELECT updated_at FROM org_baseline WHERE id=1").fetchone()
            if org:
                baselines["updated_at"] = org["updated_at"] or ""
    except Exception:
        log.exception("[UEBA] status read failed")
    return {
        "enabled": enabled,
        "env_forced_off": env_forced_off,
        "config": cfg,
        "overrides": overrides,
        "baselines": baselines,
    }


# curated lists recognized by the engine (validated by the API too)
WATCHLISTS = ("elevated", "benign")


def _load_watchlists():
    """username -> set(list names), read once per build cycle. Unknown
    list names are ignored defensively. Fail-open: an unreadable table
    must never break scoring."""
    try:
        with db() as conn:
            _ensure_ueba_tables(conn)
            rows = conn.execute(
                "SELECT username,list_name FROM watchlist").fetchall()
        out = defaultdict(set)
        for r in rows:
            if r["list_name"] in WATCHLISTS:
                out[r["username"]].add(r["list_name"])
        return out
    except Exception:
        log.exception("[UEBA] watchlist load failed (fail-open)")
        return {}


def _load_triage():
    """(username, UTC-day) -> {status, reason, triaged_by}. Fail-open."""
    try:
        with db() as conn:
            _ensure_ueba_tables(conn)
            rows = conn.execute(
                "SELECT username,triage_date,status,reason,triaged_by "
                "FROM incident_triage").fetchall()
        return {(r["username"], r["triage_date"]):
                {"status": r["status"], "reason": r["reason"] or "",
                 "triaged_by": r["triaged_by"] or ""}
                for r in rows}
    except Exception:
        log.exception("[UEBA] triage load failed (fail-open)")
        return {}


def list_watchlists():
    """All watchlist rows for the Settings -> Watchlists tab."""
    with db() as conn:
        _ensure_ueba_tables(conn)
        rows = conn.execute(
            "SELECT id,username,list_name,note,created_by,created_at "
            "FROM watchlist ORDER BY list_name, username").fetchall()
    return [dict(r) for r in rows]


def add_watchlist(username, list_name, note="", created_by=""):
    """Insert or update one (username, list_name) entry; returns row id."""
    with db() as conn:
        _ensure_ueba_tables(conn)
        cur = conn.execute(
            "INSERT INTO watchlist (username,list_name,note,created_by,created_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(username,list_name) DO UPDATE SET "
            "note=excluded.note, created_by=excluded.created_by, "
            "created_at=excluded.created_at",
            (username, list_name, (note or "")[:200], (created_by or "")[:64],
             _fmt(datetime.datetime.now(UTC))))
        return cur.lastrowid


def remove_watchlist(row_id):
    """Delete one row by id; True when something was actually removed."""
    with db() as conn:
        _ensure_ueba_tables(conn)
        return conn.execute(
            "DELETE FROM watchlist WHERE id=?", (row_id,)).rowcount > 0


def save_triage(username, triage_date, status, reason="", triaged_by="",
                rules=None):
    """Upsert the analyst verdict for (username, UTC-day).
    status: 'tp' (true positive) or 'fp' (false positive). `rules` is the
    snapshot of triggered rule names used by the per-rule quality stats."""
    if status not in ("tp", "fp"):
        raise ValueError("status must be 'tp' or 'fp'")
    with db() as conn:
        _ensure_ueba_tables(conn)
        conn.execute(
            "INSERT INTO incident_triage "
            "(username,triage_date,status,reason,triaged_by,rules_json,created_at) "
            "VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(username,triage_date) DO UPDATE SET "
            "status=excluded.status, reason=excluded.reason, "
            "triaged_by=excluded.triaged_by, rules_json=excluded.rules_json, "
            "created_at=excluded.created_at",
            (username, triage_date, status, (reason or "")[:300],
             (triaged_by or "")[:64], json.dumps(sorted(set(rules or []))),
             _fmt(datetime.datetime.now(UTC))))


def delete_triage(username, triage_date):
    """Reopen a user-day (remove the verdict); True when a row existed."""
    with db() as conn:
        _ensure_ueba_tables(conn)
        return conn.execute(
            "DELETE FROM incident_triage WHERE username=? AND triage_date=?",
            (username, triage_date)).rowcount > 0


def triage_stats():
    """Detection-quality metrics for the Incidents tab: verdict counts,
    overall precision and a per-rule tp/fp breakdown (from the rule
    snapshots stored at triage time). Fail-open on any error."""
    out = {"total": {"tp": 0, "fp": 0}, "precision": None,
           "per_rule": {}, "recent": []}
    try:
        with db() as conn:
            _ensure_ueba_tables(conn)
            rows = conn.execute(
                "SELECT username,triage_date,status,reason,triaged_by,created_at,"
                "rules_json FROM incident_triage "
                "ORDER BY created_at DESC, id DESC LIMIT 500").fetchall()
        for r in rows:
            st = r["status"] if r["status"] in ("tp", "fp") else None
            if st:
                out["total"][st] += 1
            try:
                rules = json.loads(r["rules_json"] or "[]")
            except (ValueError, TypeError):
                rules = []
            for rule in rules:
                slot = out["per_rule"].setdefault(rule, {"tp": 0, "fp": 0})
                if st:
                    slot[st] += 1
            if len(out["recent"]) < 50:
                out["recent"].append({
                    "username": r["username"], "date": r["triage_date"],
                    "status": r["status"], "reason": r["reason"] or "",
                    "by": r["triaged_by"] or "", "at": r["created_at"] or "",
                })
        tp, fp = out["total"]["tp"], out["total"]["fp"]
        if tp + fp:
            out["precision"] = round(100.0 * tp / (tp + fp), 1)
        return out
    except Exception:
        log.exception("[UEBA] triage stats failed (fail-open)")
        return out


_ueba_lock = threading.Lock()


def _pair_key(pair):
    return "|".join(sorted(pair))


def _hour_window_count(hours, h):
    """Occurrences of hour h with +-1h tolerance. People do not log in
    at exactly the same minute every day, so a single-hour histogram
    must be read with a tolerance window."""
    return (hours.get((h - 1) % 24, 0) + hours.get(h, 0) + hours.get((h + 1) % 24, 0))


def _org_hour_users(hours, h):
    """Distinct peer users active at hour h with +-1h tolerance (org
    histogram values are user lists; a set union avoids double
    counting users active in two adjacent hours)."""
    users = set()
    for k in ((h - 1) % 24, h, (h + 1) % 24):
        users.update(hours.get(k, []))
    return len(users)


def _ueba_enabled_db():
    """Hard switch: UEBA_ENABLED=false in the environment.
    Soft switch (no rebuild; sqlite3 on the host or Settings -> UEBA):
      INSERT OR REPLACE INTO settings (key,value) VALUES ('ueba_enabled','false')
    """
    if not _UEBA["enabled"]:
        return False
    return _db_ueba_enabled() is not False  # unset/unreadable -> enabled


def _ensure_ueba_tables(conn):
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS user_baselines (
            username TEXT PRIMARY KEY,
            active_days INTEGER DEFAULT 0,
            hours_json TEXT DEFAULT '{}',
            fail_median REAL DEFAULT 0,
            countries_json TEXT DEFAULT '[]',
            fast_pairs_json TEXT DEFAULT '{}',
            ad_uncov_count INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS org_baseline (
            id INTEGER PRIMARY KEY CHECK (id=1),
            users INTEGER DEFAULT 0,
            hours_json TEXT DEFAULT '{}',
            fail_median REAL,
            updated_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            list_name TEXT NOT NULL,
            note TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            created_at TEXT DEFAULT '',
            UNIQUE (username, list_name)
        );
        CREATE TABLE IF NOT EXISTS incident_triage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            triage_date TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT DEFAULT '',
            triaged_by TEXT DEFAULT '',
            rules_json TEXT DEFAULT '[]',
            created_at TEXT DEFAULT '',
            UNIQUE (username, triage_date)
        );
    ''')


def _baselines_stale(conn):
    """True when baselines were never built or are older than the TTL.
    The org_baseline row is the rebuild heartbeat (written even when
    there are no profiles at all, e.g. on a fresh install)."""
    try:
        row = conn.execute("SELECT updated_at FROM org_baseline WHERE id=1").fetchone()
        if not row:
            return True
        ts = _parse_ts(row["updated_at"])
        if ts is None:
            return False  # unreadable stamp: never trigger a rebuild loop
        return (datetime.datetime.now(UTC) - ts) > datetime.timedelta(hours=_UEBA["ttl_hours"])
    except Exception:
        return True


def rebuild_baselines(force=False):
    """(Re)build user + org baselines from event history.

    Called lazily from build_incidents when the profiles are older than
    UEBA_BASELINE_TTL_HOURS. The window is min(UEBA_BASELINE_DAYS,
    RETENTION_DAYS) days, so with the default 7-day retention the
    effective training window is the whole kept history.
    Fail-open: on error the old baselines stay in place.
    """
    if not _UEBA["enabled"]:
        return False
    if not _ueba_lock.acquire(blocking=False):
        return False  # another thread is rebuilding right now
    try:
        window_days = max(3, min(_UEBA["baseline_days"], settings.retention_days))
        cutoff = _fmt(datetime.datetime.now(UTC) - datetime.timedelta(days=window_days))
        started = time.monotonic()

        with db() as conn:
            _ensure_ueba_tables(conn)
            if not force and not _baselines_stale(conn):
                return False
            vpn_rows = [dict(r) for r in conn.execute(
                "SELECT timestamp,username,src_ip,private_ip FROM vpn_events "
                "WHERE action='login_success' AND src_ip != 'N/A' AND timestamp >= ?", (cutoff,))]
            ad_rows = [dict(r) for r in conn.execute(
                "SELECT timestamp,username,src_ip FROM ad_events "
                "WHERE action IN ('logon_success','kerberos_tgt') AND src_ip != 'N/A' AND timestamp >= ?", (cutoff,))]
            logout_rows = [dict(r) for r in conn.execute(
                "SELECT timestamp,username,private_ip FROM vpn_events "
                "WHERE action='logout' AND timestamp >= ?", (cutoff,))]
            fail_rows = []
            for table, act in (("vpn_events", "login_failed"), ("ad_events", "logon_failed")):
                fail_rows += [dict(r) for r in conn.execute(
                    f"SELECT username,SUBSTR(timestamp,1,10) day,SUM(COALESCE(event_count,1)) c "
                    f"FROM {table} WHERE action=? AND timestamp >= ? "
                    f"GROUP BY username,SUBSTR(timestamp,1,10)", (act, cutoff))]

        vpn_rows = [r for r in vpn_rows if _valid_user(r["username"])]
        ad_rows = [r for r in ad_rows
                   if _valid_user(r["username"]) and not _in_nets(r["src_ip"], settings.excluded_ad_nets)]
        users = {r["username"] for r in vpn_rows} | {r["username"] for r in ad_rows}

        geo_map = {}
        if users:
            try:
                geo_map = geo_lookup({r["src_ip"] for r in vpn_rows})
            except Exception as e:
                log.warning("[UEBA] geo lookup failed (geo baselines degraded): %s", e)

        user_vpn = defaultdict(list)
        user_ad = defaultdict(list)
        user_logout = defaultdict(list)
        for r in vpn_rows:
            user_vpn[r["username"]].append(r)
        for r in ad_rows:
            user_ad[r["username"]].append(r)
        for r in logout_rows:
            if _valid_user(r["username"]):
                user_logout[r["username"]].append(r)

        fails = defaultdict(dict)  # user -> {day: failed count}
        for r in fail_rows:
            if _valid_user(r["username"]):
                f = fails[r["username"]]
                f[r["day"]] = f.get(r["day"], 0) + r["c"]

        now = datetime.datetime.now(UTC)
        profiles = {}
        org_hours = defaultdict(set)  # hour -> established users
        org_fail_pool = []

        for user in users:
            vpn = sorted(user_vpn.get(user, []), key=lambda r: r["timestamp"])
            ad = user_ad.get(user, [])
            hours = Counter()
            days = set()
            countries = set()
            pairs = Counter()
            prev = None
            for r in vpn:
                dt = _parse_ts(r["timestamp"])
                if not dt:
                    continue
                hours[dt.hour] += 1
                days.add(r["timestamp"][:10])
                c = geo_map.get(r["src_ip"], "N/A")
                c = c.split(",")[0].strip() if c not in ("N/A", "Internal") else c
                if c not in ("N/A", "Internal"):
                    countries.add(c)
                    if prev and prev[1] not in ("N/A", "Internal") and prev[1] != c:
                        gap = (dt - prev[0]).total_seconds() / 60
                        if 0 < gap <= 120:
                            pairs[_pair_key((prev[1], c))] += 1
                prev = (dt, c)
            for r in ad:
                dt = _parse_ts(r["timestamp"])
                if dt:
                    hours[dt.hour] += 1
                    days.add(r["timestamp"][:10])
            sessions = _build_sessions(
                [(r["timestamp"], r["src_ip"], r.get("private_ip") or "N/A") for r in vpn],
                [(r["timestamp"], r.get("private_ip") or "N/A") for r in user_logout.get(user, [])])
            uncov_n = _count_ad_uncovered(
                [(r["timestamp"], r["src_ip"], "-") for r in ad], sessions)
            daily = [fails.get(user, {}).get(d, 0) for d in sorted(days)]
            profiles[user] = {
                "active_days": len(days),
                "hours": dict(hours),
                "fail_median": float(statistics.median(daily)) if daily else 0.0,
                "countries": sorted(countries),
                "fast_pairs": {p: n for p, n in pairs.items() if n >= _UEBA["pair_min"]},
                "ad_uncov_count": uncov_n,
            }
            # The peer profile is built ONLY from established users: a
            # brand-new account (possibly an attacker) must not define
            # what "normal" is for the organisation.
            if len(days) >= _UEBA["min_days"]:
                for h in hours:
                    org_hours[h].add(user)
                org_fail_pool.extend(daily)

        now_s = _fmt(now)
        org_users = sum(1 for p in profiles.values() if p["active_days"] >= _UEBA["min_days"])
        names = list(profiles)
        with db() as conn:
            if names:
                for i in range(0, len(names), 500):
                    chunk = names[i:i + 500]
                    conn.execute(
                        "DELETE FROM user_baselines WHERE username NOT IN (%s)"
                        % ",".join("?" * len(chunk)), chunk)
            else:
                conn.execute("DELETE FROM user_baselines")
            for user, p in profiles.items():
                conn.execute(
                    "INSERT OR REPLACE INTO user_baselines "
                    "(username,active_days,hours_json,fail_median,countries_json,"
                    "fast_pairs_json,ad_uncov_count,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (user, p["active_days"], json.dumps(p["hours"]), p["fail_median"],
                     json.dumps(p["countries"]), json.dumps(p["fast_pairs"]),
                     p["ad_uncov_count"], now_s))
            conn.execute(
                "INSERT OR REPLACE INTO org_baseline "
                "(id,users,hours_json,fail_median,updated_at) VALUES (1,?,?,?,?)",
                (org_users,
                 json.dumps({h: sorted(us) for h, us in org_hours.items()}),
                 float(statistics.median(org_fail_pool)) if org_fail_pool else None,
                 now_s))
        log.info("[UEBA] baselines rebuilt: %d users (window %dd) in %.1fs",
                 len(profiles), window_days, time.monotonic() - started)
        return True
    except Exception:
        log.exception("[UEBA] baseline rebuild failed (fail-open, old baselines kept)")
        return False
    finally:
        _ueba_lock.release()


def _ensure_baselines():
    """Load (profiles, org), rebuilding first when stale.
    Returns ({}, None) when disabled or on any error (fail-open)."""
    if not _ueba_enabled_db():
        return {}, None
    try:
        with db() as conn:
            _ensure_ueba_tables(conn)
            stale = _baselines_stale(conn)
        if stale:
            rebuild_baselines()
        profiles = {}
        org = None
        with db() as conn:
            for r in conn.execute(
                    "SELECT username,active_days,hours_json,fail_median,countries_json,"
                    "fast_pairs_json,ad_uncov_count FROM user_baselines"):
                try:
                    profiles[r["username"]] = {
                        "active_days": r["active_days"] or 0,
                        "hours": {int(k): v for k, v in json.loads(r["hours_json"] or "{}").items()},
                        "fail_median": float(r["fail_median"] or 0),
                        "countries": set(json.loads(r["countries_json"] or "[]")),
                        "fast_pairs": {k: v for k, v in json.loads(r["fast_pairs_json"] or "{}").items()},
                        "ad_uncov_count": r["ad_uncov_count"] or 0,
                    }
                except (ValueError, TypeError):
                    continue  # one broken row must not break scoring for everyone
            row = conn.execute(
                "SELECT users,hours_json,fail_median FROM org_baseline WHERE id=1").fetchone()
            if row:
                org = {
                    "users": row["users"] or 0,
                    "hours": {int(k): v for k, v in json.loads(row["hours_json"] or "{}").items()},
                    "fail_median": float(row["fail_median"]) if row["fail_median"] is not None else None,
                }
        return profiles, org
    except Exception:
        log.exception("[UEBA] baseline load failed (fail-open)")
        return {}, None


def _ueba_adjust(rule_score, off_hours, off_utc, multi_geo, geo_gap, gap_pair,
                 failed_n, failed_1h, ad_uncov, countries, baseline, org,
                 instant=False, watchlists=None):
    """Moderate the rule score with personal (or peer) history.

    Returns (final_score, info); info is None when UEBA is off, so the
    incident payload stays byte-identical to v1.5.0 in that case.
    Absolutes (brute-force success) are never suppressed - not even for
    benign watchlist accounts. Watchlists (v1.6.2):
      elevated - personal/peer suppression bypassed for this user;
      benign   - noise rules always suppressed (service accounts).
    instant  - scripted VPN->AD handover: +10 supporting bonus when at
    least one triggered rule survives suppression (never fires alone).
    """
    if not _UEBA["enabled"] or rule_score <= 0:
        return rule_score, None

    info = {"personal": False, "active_days": 0, "suppressed": [], "note": []}

    reliable = bool(baseline) and baseline["active_days"] >= _UEBA["min_days"]
    info["personal"] = reliable
    if baseline:
        info["active_days"] = baseline["active_days"]

    # Absolute: many failures in the LAST hour + successful auth in the
    # same window = brute-force success. Never suppressed, floors the score.
    if failed_1h >= _UEBA["abs_brute_failed"]:
        final = max(rule_score, _UEBA["abs_floor"])
        info["absolute"] = "brute_force_success"
        info["note"].append(
            "absolute: %d failed logins in the last hour + successful auth -> floored to %d"
            % (failed_1h, final))
        return final, info

    suppressed = 0
    wl = set(watchlists or ())
    if wl:
        info["watchlists"] = sorted(wl)

    if "elevated" in wl:
        # VIP / leaver / under investigation: every triggered rule stays
        info["note"].append(
            "elevated watchlist: personal/peer suppression bypassed for this user")
    elif "benign" in wl:
        # service / monitoring account: noise is always routine for it
        fired = []
        if off_hours:
            fired.append("off_hours")
        if failed_n >= settings.brute_force_threshold:
            fired.append("failed_logins")
        if multi_geo:
            fired.append("multi_geo")
            if geo_gap is not None and geo_gap <= 120:
                fired.append("impossible_travel")
        if ad_uncov:
            fired.append("ad_without_vpn")
        if instant:
            fired.append("instant_switch")
        info["suppressed"] = fired
        info["note"].append(
            "benign watchlist: routine service account, noise rules suppressed")
        suppressed = rule_score
    else:
        # off-hours (+20): the user personally, or enough established
        # peers, routinely work at these hours
        if off_hours and off_utc:
            if reliable:
                ok = all(_hour_window_count(baseline["hours"], h) >= _UEBA["hour_min_occ"]
                         for h in off_utc)
                src = "personal hours"
            elif org and org["hours"]:
                ok = all(_org_hour_users(org["hours"], h) >= _UEBA["org_hour_min_users"]
                         for h in off_utc)
                src = "org/peer hours"
            else:
                ok, src = False, ""
            if ok:
                suppressed += 20
                info["suppressed"].append("off_hours")
                info["note"].append("off_hours: typical for this user (%s)" % src)

        # failed logins (+15): within the personal (or org) daily norm
        if failed_n >= settings.brute_force_threshold:
            if reliable:
                typical = baseline["fail_median"]
            elif org and org.get("fail_median") is not None:
                typical = org["fail_median"]
            else:
                typical = None
            if typical is not None and \
                    failed_n <= typical * _UEBA["fail_mult"] + _UEBA["fail_margin"]:
                suppressed += 15
                info["suppressed"].append("failed_logins")
                info["note"].append(
                    "failed_logins: %d within the typical daily norm %.1f" % (failed_n, typical))

        # multi-geo (+35): every country is already known for this user.
        # Skipped entirely when an impossible-travel pair is present (both
        # signals then follow the fast-pair logic below).
        if multi_geo and (geo_gap is None or geo_gap > 120) and reliable:
            if countries and countries <= baseline["countries"]:
                suppressed += 35
                info["suppressed"].append("multi_geo")
                info["note"].append("multi_geo: all countries already known for this user")

        # impossible travel (+35 +25): this exact fast pair is a routine
        # for the user (commute, mobile-ISP geo flip), both countries known
        if multi_geo and geo_gap is not None and geo_gap <= 120 and reliable and gap_pair:
            n = baseline["fast_pairs"].get(_pair_key(gap_pair), 0)
            if n >= _UEBA["pair_min"] and set(gap_pair) <= baseline["countries"]:
                suppressed += 60
                info["suppressed"].append("impossible_travel")
                info["note"].append(
                    "impossible_travel: %s <-> %s seen %d times before (routine geo flip)"
                    % (gap_pair[0], gap_pair[1], n))

        # AD without VPN (+10): structural for this user (e.g. a mobile
        # mail app on a public IP outside VPN sessions)
        if ad_uncov and reliable and baseline["ad_uncov_count"] >= _UEBA["ad_uncov_min"]:
            suppressed += 10
            info["suppressed"].append("ad_without_vpn")
            info["note"].append(
                "ad_without_vpn: routine for this user (%d times in the baseline window)"
                % baseline["ad_uncov_count"])

    final = max(rule_score - suppressed, 0)

    # instant VPN->AD handover (+10, v1.6.2): a supporting signal that
    # only amplifies rules that survived suppression above. Service
    # accounts (benign) automate logins all the time - no bonus there.
    if instant and "benign" not in wl:
        supp = set(info["suppressed"])
        kept = (
            (off_hours and "off_hours" not in supp)
            or (multi_geo and "multi_geo" not in supp
                and "impossible_travel" not in supp)
            or (failed_n >= settings.brute_force_threshold
                and "failed_logins" not in supp)
        )
        if kept:
            final += 10
            info["bonus"] = ["instant_switch"]
            info["note"].append(
                "instant_switch: VPN->AD handover with no human pause (+10 supporting)")

    return final, info
