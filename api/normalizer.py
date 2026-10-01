import datetime
import json
import os
import re
from collections import defaultdict
from typing import Any, Dict, List

VPN_SIGNATURES = [
    ("VPN_LOGIN_SUCCESS", re.compile(r"ASA-4-722051|VPN user Connected|IPv4 Address.*assigned to session", re.I)),
    ("VPN_LOGIN_FAILED", re.compile(r"ASA-6-113005|AAA user authentication Rejected|Unsuccessful VPN-Firewall Logon", re.I)),
    ("VPN_LOGOUT", re.compile(r"ASA-6-716002|WebVPN session terminated|VPN user Disconnected", re.I)),
    ("VPN_LOGON_START", re.compile(r"ASA-6-716001|WebVPN session started", re.I)),
    ("VPN_SESSION_START", re.compile(r"ASA-6-113039|AnyConnect parent session started", re.I)),
    ("VPN_ACCOUNTING", re.compile(r"ASA-6-113004|AAA user accounting Successful", re.I)),
]

TECHNICAL_IPS = {x.strip() for x in os.getenv(
    "TECHNICAL_IPS", "10.77.36.11,10.77.1.3,0.0.0.0,127.0.0.1,255.255.255.255,::"
).split(",") if x.strip()}


def extract_ip_from_failed_auth(msg):
    if not msg:
        return "N/A"
    m = re.search(r"user\s*IP\s*[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", msg, re.I)
    return m.group(1) if m else "N/A"


def extract_ip_from_vpn_message(msg):
    if not msg:
        return "N/A"
    m = re.search(r"User\s*<[^>]+>\s*IP\s*<(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>", msg, re.I)
    if m:
        return m.group(1)
    m = re.search(r"IP\s*<(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>", msg, re.I)
    if m and m.group(1) not in TECHNICAL_IPS:
        return m.group(1)
    return "N/A"


def classify_vpn_event(raw_log):
    msg = (raw_log.get("MESSAGE", "") or "") + " " + (raw_log.get("IENAME", "") or "") + " " + (raw_log.get("SOURCE", "") or "")
    for event_type, pattern in VPN_SIGNATURES:
        if pattern.search(msg):
            return event_type
    return "UNKNOWN"


def convert_timestamp(ts_raw):
    """Normalize supported timestamps to 'YYYY-MM-DD HH:MM:SS' (UTC).

    Handles: epoch sec/ms, ISO 8601 ('T' separator, 'Z', UTC offset,
    fractional seconds), naive 'YYYY-MM-DD HH:MM:SS'.
    Naive values are assumed UTC (same assumption the pipeline always
    made for these SIEM feeds).
    """
    if not ts_raw:
        return "N/A"
    raw = str(ts_raw).strip()

    # epoch seconds / milliseconds
    if isinstance(ts_raw, (int, float)) or raw.isdigit():
        try:
            ts = int(float(raw))
            if ts > 1e12:          # milliseconds
                ts //= 1000
            if ts > 1e9:           # plausible unix epoch
                return datetime.datetime.fromtimestamp(
                    ts, tz=datetime.timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OverflowError, OSError):
            pass
        # not epoch-like -> fall through to string formats

    # ISO 8601 / space-separated, optional offset or 'Z'
    iso = raw.replace("Z", "+00:00").replace("z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass

    return raw[:19]


def normalize_vpn_log(raw_log):
    msg = raw_log.get("MESSAGE", "") or ""
    event_type = classify_vpn_event(raw_log)
    username = raw_log.get("USERNAME") or raw_log.get("USER") or "N/A"
    if (username in ("N/A", "*****")) and msg:
        m = re.search(r"User\s*<([^>]+)>", msg, re.I) or re.search(r"user\s*[=:]\s*(\S+)", msg, re.I)
        if m:
            username = m.group(1).rstrip(",")

    src_ip = "N/A"
    if event_type == "VPN_LOGIN_FAILED":
        src_ip = raw_log.get("SOURCE_IP") or extract_ip_from_failed_auth(msg)
    elif event_type in ("VPN_LOGIN_SUCCESS", "VPN_LOGOUT", "VPN_LOGON_START", "VPN_SESSION_START"):
        remote_host = raw_log.get("REMOTEHOST", "")
        if remote_host and remote_host not in TECHNICAL_IPS and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(remote_host)):
            src_ip = str(remote_host)
        if src_ip == "N/A":
            src_ip = extract_ip_from_vpn_message(msg)

    private_ip = raw_log.get("PRIVATE_IP") or raw_log.get("FIELD5") or "N/A"
    if private_ip == "N/A" and msg:
        m = re.search(r"IPv4\s+[Aa]ddress\s*<(\d{1,3}(?:\.\d{1,3}){3})>", msg)
        if m:
            private_ip = m.group(1)

    return {
        "timestamp": convert_timestamp(raw_log.get("TIME") or raw_log.get("TIMESTAMP")),
        "username": username, "src_ip": src_ip,
        "private_ip": private_ip,
        "action": event_type.replace("VPN_", "").lower(),
        "event_type": event_type,
        "raw_message": msg[:2000],
        "device": raw_log.get("HOSTNAME", "N/A"),
        "source_type": "VPN"
    }


def normalize_adap_log(raw_log):
    msg = raw_log.get("MESSAGE", "") or ""

    parsed = {}
    for match in re.finditer(r"\[\s*([A-Z_]+)\s*=\s*([^\]]*?)\s*\]", msg):
        key, value = match.group(1), match.group(2).strip()
        if value.lower() not in ("null", "-", ""):
            parsed[key] = value

    # ADAudit Plus emits USER_NAME / DOMAIN_NAME inside MESSAGE while
    # top-level fields use USERNAME / DOMAIN - accept both spellings
    # (MESSAGE fallback fires when top-level fields are absent).
    username = (raw_log.get("USERNAME")
                or parsed.get("USERNAME")
                or parsed.get("USER_NAME")
                or "N/A")
    src_ip = parsed.get("CLIENT_IP_ADDRESS") or raw_log.get("REMOTEIP") or "N/A"
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(src_ip)):
        src_ip = raw_log.get("REMOTEIP", "N/A")

    hostname = parsed.get("CLIENT_HOST_NAME") or raw_log.get("REMOTEHOST") or "N/A"
    domain = (raw_log.get("DOMAIN")
              or parsed.get("DOMAIN")
              or parsed.get("DOMAIN_NAME")
              or "N/A")
    time_gen = raw_log.get("TIME") or parsed.get("TIME_GENERATED")
    event_num = str(raw_log.get("EVENTID") or parsed.get("EVENT_NUMBER", ""))
    event_text = (raw_log.get("EVENT_TYPE_TEXT") or parsed.get("EVENT_TYPE_TEXT", "")).lower()
    remarks = parsed.get("REMARKS", "")

    action = "unknown"
    if event_num == "4768": action = "kerberos_tgt"
    elif event_num == "4724": action = "password_reset"
    elif event_num == "4740": action = "account_lockout"
    elif event_num == "4722": action = "account_enabled"
    elif event_num == "4725": action = "account_disabled"
    elif event_num == "4624" or event_text == "success": action = "logon_success"
    elif event_num == "4625" or event_text == "failure": action = "logon_failed"

    return {
        "timestamp": convert_timestamp(time_gen),
        "username": username, "domain": domain,
        "src_ip": src_ip, "hostname": hostname,
        "action": action,
        "event_type": f"ADAP_{event_num}",
        "raw_message": (remarks or msg)[:2000],
        "source_type": "ADAP"
    }


def deduplicate_and_aggregate(logs):
    bucket = defaultdict(list)
    for log in logs:
        key = (log.get("username"), log.get("src_ip"), log.get("event_type"), log.get("source_type", ""))
        bucket[key].append(log)

    result = []
    for key, events in bucket.items():
        events.sort(key=lambda x: str(x.get("timestamp", "")))
        first = events[0].copy()
        if len(events) > 1:
            first["raw_message"] = (first.get("raw_message") or "")[:1900] + f" [+{len(events)-1} similar]"
            first["event_count"] = len(events)
        else:
            first["event_count"] = 1
        result.append(first)
    return result


def estimate_tokens(text):
    """Conservative token estimate for LLM chunk budgeting.

    len//4 badly underestimates JSON-heavy data on Qwen tokenizers:
    IPs, timestamps and numbers cost ~1 token per 1-2 chars. A real
    production chunk (25 users) measured 9636 tokens against a 2000
    estimate and overflowed the 8192 context. 0.45 tokens/char matches
    measured usage while staying slightly conservative.
    """
    return int(len(text) * 0.45)


def chunk_logs(logs, max_tokens=6000):
    chunks, current, size = [], [], 0
    for log in logs:
        log_size = estimate_tokens(json.dumps(log, default=str))
        if size + log_size > max_tokens and current:
            chunks.append(current)
            current, size = [], 0
        current.append(log)
        size += log_size
    if current:
        chunks.append(current)
    return chunks