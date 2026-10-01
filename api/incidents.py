import datetime
import ipaddress
import logging
from collections import defaultdict
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
    """
    threshold = settings.incident_min_score if usernames is None else 0
    cutoff = _fmt(datetime.datetime.now(UTC) - datetime.timedelta(hours=24))
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
                    f"SELECT username,COUNT(*) c FROM {table} WHERE action=? AND timestamp >= ? GROUP BY username",
                    (act, cutoff)):
                if _valid_user(r["username"]):
                    failed[r["username"]] += r["c"]

    vpn_rows = [r for r in vpn_rows if _valid_user(r["username"])]
    ad_rows = [r for r in ad_rows if _valid_user(r["username"]) and not _in_nets(r["src_ip"], settings.excluded_ad_nets)]
    if usernames is not None:
        vpn_rows = [r for r in vpn_rows if r["username"] in usernames]
        ad_rows = [r for r in ad_rows if r["username"] in usernames]

    common = {r["username"] for r in vpn_rows} & {r["username"] for r in ad_rows}
    if not common:
        return []

    return _build_all(common, vpn_rows, ad_rows, logout_rows, failed, threshold)


def _build_all(common, vpn_rows, ad_rows, logout_rows, failed, min_score=0):
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

    incidents = []
    filtered_out = 0
    for user in common:
        inc = _build_one(user, user_vpn[user], user_ad[user],
                         user_logout[user], failed.get(user, 0),
                         geo_map, cached.get(user), min_score)
        if inc:
            incidents.append(inc)
        else:
            filtered_out += 1

    log.info("[INCIDENTS] %d built, %d below threshold (min_score=%d)",
             len(incidents), filtered_out, min_score)

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


def _build_one(user, u_vpn, u_ad, u_logout, failed_n, geo_map, cached, min_score=0):
    default_tz = ZoneInfo(settings.timezone)

    sessions = _build_sessions(u_vpn, u_logout)
    ad_uncov = _check_ad_coverage(u_ad, sessions)
    off_hours = _check_off_hours(u_vpn, u_ad, default_tz)
    multi_geo, geo_gap = _check_geo(u_vpn, geo_map)
    min_diff = _calc_min_diff(u_vpn, u_ad)
    score = _calc_score(multi_geo, geo_gap, off_hours, failed_n, ad_uncov)

    # Below the incident threshold: not suspicious enough to be an
    # incident (clean users, office workers with only ad-no-vpn etc.)
    if score < min_score:
        return None

    severity = _calc_severity(score)
    details = _build_details(u_vpn, u_ad, geo_map)

    ai_v, ai_r = cached or ("not_analyzed", "N/A")

    times = [t for t, _, _ in u_vpn] + [t for t, _, _ in u_ad]

    return {
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


def _build_sessions(u_vpn, u_logout):
    sessions = []
    for ts, _, priv in u_vpn:
        end = None
        for lts, lpriv in u_logout:
            if lts >= ts and lpriv == priv:
                end = lts if end is None else min(end, lts)
        sessions.append((ts, end, priv))
    return sessions


def _check_ad_coverage(u_ad, sessions):
    """True if any AD authentication cannot be explained by corporate
    network presence or an active VPN session.

    - AD src_ip internal (office LAN, VPN pool): normal - the user is
      already inside the perimeter, VPN is not required.
    - AD src_ip public: must fall inside a VPN session window
      ([login-15m, logout+15m], or within +-2h of any VPN login),
      otherwise flagged - that is perimeter bypass.
    """
    GRACE = datetime.timedelta(minutes=15)
    COARSE = datetime.timedelta(hours=2)
    vpn_times = [t for t in (_parse_ts(s) for s, _, _ in sessions) if t]
    now = datetime.datetime.now(UTC)

    for ts, ip, _ in u_ad:
        if _is_internal_ip(ip):
            continue  # office / VPN internal address - no VPN required

        tdt = _parse_ts(ts)
        if not tdt:
            continue

        covered = False
        for s, e, priv in sessions:
            sdt = _parse_ts(s)
            if not sdt:
                continue
            hi = (_parse_ts(e) or now) + GRACE
            if (sdt - GRACE) <= tdt <= hi:
                covered = True
                break
        if not covered:
            for v in vpn_times:
                if abs((tdt - v).total_seconds()) <= COARSE.total_seconds():
                    covered = True
                    break
        if not covered:
            return True
    return False


def _check_off_hours(u_vpn, u_ad, default_tz):
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

    def hour(t):
        dt = _parse_ts(t)
        return dt.astimezone(user_tz).hour if dt else 12

    return any(hour(t) >= settings.off_hours_start or hour(t) < settings.off_hours_end for t in times)


def _check_geo(u_vpn, geo_map):
    entries = sorted((t, geo_map.get(ip, "N/A")) for t, ip, _ in u_vpn)
    countries = [(t, g.split(",")[0].strip() if g not in ("N/A", "Internal") else g) for t, g in entries]

    geo_gap = None
    for i in range(1, len(countries)):
        c0, c1 = countries[i - 1][1], countries[i][1]
        if c0 != c1 and "N/A" not in (c0, c1) and "Internal" not in (c0, c1):
            t0, t1 = _parse_ts(countries[i - 1][0]), _parse_ts(countries[i][0])
            if t0 and t1:
                d = (t1 - t0).total_seconds() / 60
                geo_gap = d if geo_gap is None else min(geo_gap, d)

    multi_geo = len({c for _, c in countries if c not in ("N/A", "Internal")}) > 1
    return multi_geo, geo_gap


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


def _build_details(u_vpn, u_ad, geo_map):
    details = [{"time": t, "source": "VPN", "ip": ip,
                "geo": geo_map.get(ip, "N/A"), "host": priv} for t, ip, priv in u_vpn]
    details += [{"time": t, "source": "AD", "ip": ip, "geo": "-", "host": host} for t, ip, host in u_ad]
    details.sort(key=lambda x: x["time"], reverse=True)
    return details