import datetime
import json
import logging
from zoneinfo import ZoneInfo

import httpx

from config import settings
from database import db

log = logging.getLogger("alerter")

UTC = datetime.timezone.utc
FMT = "%Y-%m-%d %H:%M:%S"
SEV_ORDER = ["info", "low", "medium", "high"]


def _get_telegram_config():
    cfg = {
        "bot_token": "", "chat_id": "",
        "enabled": False, "min_severity": "medium"
    }
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='telegram_config'").fetchone()
    if row and row["value"]:
        try:
            cfg.update(json.loads(row["value"]))
        except Exception:
            pass
    return cfg


def save_telegram_config(cfg):
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key,value) VALUES ('telegram_config', ?)",
            (json.dumps(cfg),))
    return cfg


def _send(token, chat_id, text):
    url = "https://api.telegram.org/bot" + token + "/sendMessage"
    try:
        with httpx.Client(proxy=settings.tg_proxy or None, timeout=10.0) as client:
            r = client.post(url, json={
                "chat_id": chat_id, "text": text,
                "parse_mode": "HTML"
            })
            if r.status_code == 200:
                return True
            log.error("TG: %s", r.text[:200])
            return False
    except Exception as e:
        log.error("TG fail (proxy=%s): %s", settings.tg_proxy or "direct", e)
        return False


def _fmt_local(ts):
    """Format a UTC timestamp string in the configured local timezone
    (ANALYSIS_TZ, e.g. Europe/Moscow -> '2026-10-01 07:31:17 MSK').
    Falls back to the raw value labelled UTC."""
    for f in (FMT, "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.datetime.strptime(str(ts), f).replace(tzinfo=UTC)
            loc = dt.astimezone(ZoneInfo(settings.timezone))
            label = loc.tzname() or settings.timezone
            return loc.strftime(FMT) + " " + label
        except ValueError:
            continue
        except Exception:
            break
    return str(ts) + " UTC"


def _alert_key(inc):
    return "|".join((
        inc.get("username", "?"),
        str(inc.get("last_seen", "")),
        inc.get("severity", ""),
    ))


def _already_alerted(inc):
    """True if this exact incident state was already alerted,
    or the user is inside the re-alert cooldown window."""
    user = inc.get("username", "?")
    cutoff = (datetime.datetime.now(UTC)
              - datetime.timedelta(minutes=settings.alert_cooldown_min)
              ).strftime(FMT)
    with db() as conn:
        if conn.execute(
                "SELECT 1 FROM alert_log WHERE alert_key=?",
                (_alert_key(inc),)).fetchone():
            return True
        if conn.execute(
                "SELECT 1 FROM alert_log WHERE username=? AND sent_at>=?",
                (user, cutoff)).fetchone():
            return True
    return False


def _mark_alerted(inc):
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO alert_log (username,alert_key,severity,sent_at) VALUES (?,?,?,?)",
            (inc.get("username", "?"), _alert_key(inc), inc.get("severity", ""),
             datetime.datetime.now(UTC).strftime(FMT)))


def _format_incident(inc):
    sev = inc.get("severity", "info")
    score = inc.get("risk_score", 0)
    ai = inc.get("ai_verdict", "not_analyzed")

    lines = [
        "[SOC-ALERT] " + sev.upper() + " | Score: " + str(score)
    ]

    user = inc.get("username", "?")
    lines.append("User: " + user)

    last = inc.get("last_seen", "")
    if last:
        lines.append("Time: " + _fmt_local(last))

    signals = []
    if inc.get("off_hours"):
        signals.append("- Off-hours access")
    if inc.get("multi_geo"):
        gap = inc.get("geo_gap_min")
        geo = str(inc.get("vpn_geo", ""))[:60].replace(" | ", " -> ")
        sig = "- Multi-geo"
        if gap:
            sig += " (" + str(gap) + " min gap)"
        if geo:
            sig += ": " + geo
        signals.append(sig)
    if inc.get("ad_without_vpn"):
        signals.append("- AD login without VPN session")
    failed = inc.get("failed_logins", 0)
    if failed:
        signals.append("- Failed logins: " + str(failed))

    if signals:
        lines.append("")
        lines.append("DETECTED:")
        lines.extend(signals)

    lines.append("")
    lines.append("AI VERDICT: " + ai.upper())

    reason = inc.get("ai_reason", "")
    if reason and reason != "N/A":
        lines.append("Analysis: " + str(reason)[:150])

    vpn = inc.get("vpn_count", 0)
    ad = inc.get("ad_count", 0)
    lines.append("")
    lines.append("Severity: " + sev.upper() + " | VPN: " + str(vpn) + " | AD: " + str(ad) + " | Failed: " + str(failed))

    return "\n".join(lines)


def send_alert(incidents):
    cfg = _get_telegram_config()
    if not cfg.get("enabled"):
        return 0
    token = cfg.get("bot_token", "")
    chat_id = cfg.get("chat_id", "")
    if not token or not chat_id:
        return 0

    min_sev = cfg.get("min_severity", "medium")
    mi = SEV_ORDER.index(min_sev) if min_sev in SEV_ORDER else 2

    sent = 0
    for inc in incidents:
        sev = inc.get("severity", "info")
        si = SEV_ORDER.index(sev) if sev in SEV_ORDER else 0
        if si < mi and inc.get("ai_verdict") != "malicious":
            continue
        if _already_alerted(inc):
            continue
        text = _format_incident(inc)
        if _send(token, chat_id, text):
            _mark_alerted(inc)
            sent += 1
        else:
            # Telegram down: marks not written -> retried next cycle
            break

    if sent > 0:
        log.info("[TG] sent %d", sent)
    return sent


def test_telegram(cfg):
    if not cfg.get("bot_token"):
        return {"ok": False, "msg": "no token"}
    if not cfg.get("chat_id"):
        return {"ok": False, "msg": "no chat"}

    test_inc = {
        "username": "test_user", "severity": "high",
        "risk_score": 85, "ai_verdict": "suspicious",
        "ai_reason": "Test message from SOC LLM",
        "off_hours": True, "multi_geo": True,
        "geo_gap_min": 45, "ad_without_vpn": False,
        "failed_logins": 3, "vpn_count": 2,
        "ad_count": 4, "vpn_geo": "Russia, Moscow | Brazil, Sao Paulo",
        "last_seen": "2026-09-25 14:30:00"
    }

    text = _format_incident(test_inc)
    ok = _send(cfg["bot_token"], cfg["chat_id"], text)
    return {"ok": ok, "msg": "sent" if ok else "failed"}