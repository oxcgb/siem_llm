import datetime
import ipaddress
import logging

import httpx

from config import settings
from database import db

log = logging.getLogger("geo")
GEO_TTL_DAYS = 30

_reader = None
_reader_tried = False
_external_warned = False


def _mmdb():
    global _reader, _reader_tried
    if _reader_tried:
        return _reader
    _reader_tried = True
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(f"{settings.data_dir}/GeoLite2-City.mmdb")
        log.info("GeoIP: local DB loaded")
    except Exception:
        _reader = None
        log.info("GeoIP: mmdb not found")
    return _reader


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved or a.is_link_local or a.is_multicast)
    except ValueError:
        return False


def lookup(ips):
    global _external_warned
    result, to_resolve = {}, []
    now = datetime.datetime.now(datetime.timezone.utc)
    fresh_limit = (now - datetime.timedelta(days=GEO_TTL_DAYS)).strftime("%Y-%m-%d %H:%M:%S")

    # batch cache read (was one SELECT per IP)
    unique = [i for i in {i for i in ips if i}]
    cached = {}
    for i in range(0, len(unique), 500):
        chunk = unique[i:i + 500]
        q = ",".join("?" * len(chunk))
        with db() as conn:
            for row in conn.execute(
                    f"SELECT ip,geo,timezone,fetched_at FROM geo_cache WHERE ip IN ({q})",
                    chunk):
                cached[row["ip"]] = row

    for ip in unique:
        if not _is_public(ip):
            result[ip] = "Internal"
            continue
        row = cached.get(ip)
        if row and (row["fetched_at"] or "") >= fresh_limit:
            result[ip] = row["geo"]
        else:
            to_resolve.append(ip)

    if not to_resolve:
        return result

    resolved = {}
    provider = settings.geo_provider
    if provider != "none":
        reader = _mmdb()
        if reader:
            for ip in to_resolve:
                try:
                    c = reader.city(ip)
                    geo = c.country.name or "Unknown"
                    if c.city and c.city.name:
                        geo += f", {c.city.name}"
                    tz = c.location and c.location.time_zone or ""
                    resolved[ip] = geo + "|" + (tz or "")
                except Exception:
                    pass
        elif provider in ("external", "auto"):
            if not _external_warned:
                log.warning("GeoIP: external fallback INSECURE")
                _external_warned = True
            for i in range(0, len(to_resolve), 100):
                try:
                    r = httpx.post(
                        "http://ip-api.com/batch?fields=query,country,city,timezone",
                        json=to_resolve[i:i + 100], timeout=5.0)
                    if r.status_code == 200:
                        for item in r.json():
                            ip = item.get("query")
                            if ip:
                                country = item.get("country") or "Unknown"
                                city = item.get("city") or ""
                                tz = item.get("timezone") or ""
                                geo = f"{country}, {city}" if city else country
                                resolved[ip] = geo + "|" + (tz or "")
                except Exception as e:
                    log.warning("GeoIP: %s", e)
                    break

    if resolved:
        now_s = now.strftime("%Y-%m-%d %H:%M:%S")
        with db() as conn:
            for ip, full in resolved.items():
                parts = full.split("|")
                display = parts[0]
                tz_name = parts[1] if len(parts) > 1 else ""
                conn.execute(
                    "INSERT OR REPLACE INTO geo_cache (ip,geo,timezone,fetched_at) VALUES (?,?,?,?)",
                    (ip, display, tz_name, now_s))

    for ip in to_resolve:
        parts = resolved.get(ip, "N/A|").split("|")
        result[ip] = parts[0]
    return result


def get_timezone_for_ip(ip):
    with db() as conn:
        row = conn.execute("SELECT timezone FROM geo_cache WHERE ip=?", (ip,)).fetchone()
    if row and row["timezone"]:
        return row["timezone"]
    return ""