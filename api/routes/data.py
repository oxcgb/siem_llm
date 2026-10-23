import datetime
import json
import logging
import uuid
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query
from pydantic import BaseModel

from agent import fetch_and_store_logs, run_playbook, run_network_analysis
from config import settings
from database import db
from security import (
    require_api_key, decrypt_secret,
    encrypt_secret, mask_token,
    is_allowed_target
)
from state import FETCH_STATUS, TRIAGE_STATUS, auto_triage_enabled
from audit import audit
from .auth import require_session, require_admin, sess_user

log = logging.getLogger("data")


def _valid(u):
    return bool(u) and u not in ("N/A", "ERROR", "*****", "")


data_router = APIRouter(
    dependencies=[
        Depends(require_api_key),
        Depends(require_session)
    ]
)


class DSSchema(BaseModel):
    name: str = ""
    api_url: str = ""
    auth_header: Optional[str] = None
    payload_json: str = "{}"


@data_router.get("/api/datasources")
def get_ds():
    with db() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM datasources").fetchall()]
    for r in rows:
        stored = r["auth_header"] or ""
        plain = decrypt_secret(stored)
        r["auth_header"] = mask_token(plain)
        r["has_token"] = bool(stored)
        r["token_invalid"] = bool(stored) and not plain
    return rows


@data_router.post("/api/datasources")
def add_ds(ds: DSSchema, sess=Depends(require_admin)):
    if not is_allowed_target(ds.api_url):
        raise HTTPException(400, "URL denied")
    with db() as conn:
        conn.execute(
            "INSERT INTO datasources (id,name,api_url,auth_header,payload_json) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), ds.name, ds.api_url,
             encrypt_secret(ds.auth_header or ""), ds.payload_json)
        )
    audit(sess_user(sess), "ds_add", ds.name)
    return {"status": "ok"}


@data_router.put("/api/datasources/{ds_id}")
def update_ds(ds_id: str, ds: DSSchema, sess=Depends(require_admin)):
    if not is_allowed_target(ds.api_url):
        raise HTTPException(400, "URL denied")
    with db() as conn:
        row = conn.execute("SELECT auth_header FROM datasources WHERE id=?", (ds_id,)).fetchone()
        if not row:
            raise HTTPException(404)
        token = encrypt_secret(ds.auth_header) if ds.auth_header else row["auth_header"]
        conn.execute(
            "UPDATE datasources SET name=?,api_url=?,auth_header=?,payload_json=? WHERE id=?",
            (ds.name, ds.api_url, token, ds.payload_json, ds_id)
        )
    audit(sess_user(sess), "ds_update", ds.name)
    return {"status": "ok"}


@data_router.delete("/api/datasources/{ds_id}")
def delete_ds(ds_id: str, sess=Depends(require_admin)):
    with db() as conn:
        conn.execute("DELETE FROM datasources WHERE id=?", (ds_id,))
    audit(sess_user(sess), "ds_delete", ds_id)
    return {"status": "ok"}


class RuleSchema(BaseModel):
    name: str = ""
    description: str = ""
    prompt: str = ""
    depth: str = "standard"
    window_hours: int = 24


@data_router.get("/api/rules")
def get_rules():
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM correlation_rules").fetchall()]


@data_router.post("/api/rules")
def add_rule(rule: RuleSchema, sess=Depends(require_admin)):
    if rule.depth not in ("quick", "standard", "deep"):
        raise HTTPException(400, "depth")
    wh = max(1, min(168, rule.window_hours or 24))
    with db() as conn:
        conn.execute(
            "INSERT INTO correlation_rules (id,name,description,prompt,depth,window_hours) VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), rule.name, rule.description, rule.prompt, rule.depth, wh)
        )
    audit(sess_user(sess), "rule_add", rule.name)
    return {"status": "ok"}


@data_router.put("/api/rules/{rule_id}")
def update_rule(rule_id: str, rule: RuleSchema, sess=Depends(require_admin)):
    if rule.depth not in ("quick", "standard", "deep"):
        raise HTTPException(400, "depth")
    wh = max(1, min(168, rule.window_hours or 24))
    with db() as conn:
        conn.execute(
            "UPDATE correlation_rules SET name=?,description=?,prompt=?,depth=?,window_hours=? WHERE id=?",
            (rule.name, rule.description, rule.prompt, rule.depth, wh, rule_id)
        )
    audit(sess_user(sess), "rule_update", rule.name)
    return {"status": "ok"}


@data_router.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str, sess=Depends(require_admin)):
    with db() as conn:
        conn.execute("DELETE FROM correlation_rules WHERE id=?", (rule_id,))
    audit(sess_user(sess), "rule_delete", rule_id)
    return {"status": "ok"}


@data_router.post("/api/correlate/{rule_id}")
def run_rule(rule_id: str, bg: BackgroundTasks, sess=Depends(require_session)):
    with db() as conn:
        row = conn.execute("SELECT name FROM correlation_rules WHERE id=?", (rule_id,)).fetchone()
    if not row:
        raise HTTPException(404, "rule not found")
    audit(sess_user(sess), "playbook_run", row["name"] or rule_id)
    bg.add_task(run_playbook, rule_id)
    return {"status": "started"}


@data_router.post("/api/fetch")
def fetch_all(bg: BackgroundTasks, sess=Depends(require_session)):
    audit(sess_user(sess), "fetch", "all")
    bg.add_task(fetch_and_store_logs, "manual", True)
    return {"status": "started"}


@data_router.post("/api/network-analyze")
def network_analyze(bg: BackgroundTasks, sess=Depends(require_session)):
    audit(sess_user(sess), "network_analyze")
    bg.add_task(run_network_analysis)
    return {"status": "started"}


@data_router.get("/api/fetch-status")
def fetch_status():
    return FETCH_STATUS


@data_router.get("/api/report-status")
def report_status():
    from state import REPORT_STATUS
    return REPORT_STATUS


@data_router.get("/api/playbook-runs")
def list_runs(limit: int = Query(20, ge=1, le=100)):
    with db() as conn:
        rows = conn.execute(
            "SELECT id,rule_id,rule_name,depth,status,started_at,finished_at,total,analyzed,error "
            "FROM playbook_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"runs": [dict(r) for r in rows]}


@data_router.get("/api/playbook-runs/{run_id}")
def get_run(run_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM playbook_runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        raise HTTPException(404, "run not found")
    d = dict(row)
    try:
        d["events"] = json.loads(d.pop("results_json") or "[]")
    except Exception:
        d["events"] = []
    return d


@data_router.delete("/api/playbook-runs/{run_id}")
def delete_run(run_id: int, sess=Depends(require_admin)):
    with db() as conn:
        cur = conn.execute("DELETE FROM playbook_runs WHERE id=?", (run_id,))
    if not cur.rowcount:
        raise HTTPException(404, "run not found")
    audit(sess_user(sess), "run_delete", str(run_id))
    return {"status": "ok"}


def _paged_events(table, cols, q, hours, limit, offset):
    where, params = [], []
    if hours:
        cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        where.append("timestamp >= ?")
        params.append(cutoff)
    if q:
        like = f"%{q}%"
        where.append("(" + " OR ".join(f"{c} LIKE ?" for c in cols) + ")")
        params += [like] * len(cols)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    with db() as conn:
        total = conn.execute(f"SELECT COUNT(*) c FROM {table} {w}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM {table} {w} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
    return {"events": [dict(r) for r in rows], "total": total}


@data_router.get("/api/vpn-events")
def get_vpn_events(
    q: str = Query("", max_length=100),
    hours: int = Query(0, ge=0, le=2160),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    return _paged_events("vpn_events", ["username", "src_ip", "private_ip", "action", "raw_event"], q, hours, limit, offset)


@data_router.get("/api/ad-events")
def get_ad_events(
    q: str = Query("", max_length=100),
    hours: int = Query(0, ge=0, le=2160),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    return _paged_events("ad_events", ["username", "src_ip", "hostname", "domain", "action", "raw_event"], q, hours, limit, offset)


@data_router.get("/api/network-events")
def get_network_events(
    q: str = Query("", max_length=100),
    hours: int = Query(24, ge=1, le=2160),
    action: str = Query("", max_length=40),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    where = ["timestamp >= ?"]
    params = [cutoff]
    if action:
        where.append("action = ?")
        params.append(action)
    if q:
        like = f"%{q}%"
        where.append("(subject LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR acl LIKE ? OR raw_event LIKE ?)")
        params += [like] * 5
    w = "WHERE " + " AND ".join(where)
    with db() as conn:
        total = conn.execute(f"SELECT COUNT(*) c FROM network_events {w}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM network_events {w} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
    return {"events": [dict(r) for r in rows], "total": total}


def _ip_is_public(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip))
        return not (a.is_private or a.is_loopback or a.is_reserved or a.is_link_local)
    except ValueError:
        return False


@data_router.get("/api/network-summary")
def network_summary(hours: int = Query(24, ge=1, le=2160)):
    from geo import lookup as geo_lookup
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        actions = [dict(r) for r in conn.execute(
            "SELECT action, COUNT(*) n, SUM(event_count) total_hits "
            "FROM network_events WHERE timestamp >= ? GROUP BY action ORDER BY n DESC",
            (cutoff,))]
        subjects = [dict(r) for r in conn.execute(
            "SELECT subject, subject_kind, COUNT(*) n, SUM(event_count) hits, "
            "MAX(avg_ratio) max_ratio, MAX(avg_rate) avg_rate, MAX(avg_max) avg_max, "
            "MAX(cumulative) max_cumulative, MAX(timestamp) last_seen "
            "FROM network_events WHERE timestamp >= ? AND action='drop_rate_exceeded' "
            "GROUP BY subject ORDER BY hits DESC LIMIT 60", (cutoff,))]
        denied_dst = [dict(r) for r in conn.execute(
            "SELECT dst_ip, COUNT(*) n, SUM(event_count) hits, MAX(timestamp) last_seen "
            "FROM network_events WHERE timestamp >= ? AND action IN ('denied','acl_denied') "
            "AND dst_ip != 'N/A' GROUP BY dst_ip ORDER BY hits DESC LIMIT 15", (cutoff,))]
        outbound = [dict(r) for r in conn.execute(
            "SELECT src_ip, dst_ip, dst_port, protocol, COUNT(*) n, SUM(event_count) hits, "
            "MAX(timestamp) last_seen FROM network_events "
            "WHERE timestamp >= ? AND action='acl_denied' "
            "GROUP BY src_ip, dst_ip, dst_port ORDER BY hits DESC LIMIT 20", (cutoff,))]
        flows = [dict(r) for r in conn.execute(
            "SELECT src_ip, COUNT(*) n, SUM(event_count) hits, "
            "COUNT(DISTINCT dst_ip) uniq_dst, COUNT(DISTINCT dst_port) uniq_ports, "
            "MAX(timestamp) last_seen "
            "FROM network_events "
            "WHERE timestamp >= ? AND action IN ('acl_denied','deny_no_conn','denied') "
            "AND src_ip != 'N/A' GROUP BY src_ip ORDER BY hits DESC LIMIT 30", (cutoff,))]
        bruteforce = [dict(r) for r in conn.execute(
            "SELECT src_ip, SUM(COALESCE(event_count,1)) attempts, "
            "COUNT(DISTINCT username) uniq_names, "
            "MIN(timestamp) first_seen, MAX(timestamp) last_seen "
            "FROM vpn_events WHERE timestamp >= ? AND action='login_failed' "
            "AND src_ip != 'N/A' GROUP BY src_ip "
            "HAVING attempts >= 10 ORDER BY attempts DESC LIMIT 15", (cutoff,))]

    external = [s for s in subjects
                if s["subject_kind"] == "ip" and _ip_is_public(s["subject"])]
    internal = [s for s in subjects
                if s["subject_kind"] == "ip" and not _ip_is_public(s["subject"])]
    categories = [s for s in subjects if s["subject_kind"] == "category"]
    protos = [s for s in subjects if s["subject_kind"] == "proto"]

    external_flows = [f for f in flows if _ip_is_public(f["src_ip"])]
    for f in external_flows:
        f["scanner"] = (f.get("uniq_ports") or 0) >= 3

    bruteforce = [b for b in bruteforce if _ip_is_public(b["src_ip"])]
    geo_ips = ({s["subject"] for s in external}
               | {f["src_ip"] for f in external_flows}
               | {b["src_ip"] for b in bruteforce})
    if geo_ips:
        geo = geo_lookup(geo_ips)
        for s in external:
            s["geo"] = geo.get(s["subject"], "N/A")
        for f in external_flows:
            f["geo"] = geo.get(f["src_ip"], "N/A")

    return {"actions": actions,
            "bruteforce": bruteforce,
            "external": external, "external_flows": external_flows,
            "categories": categories,
            "internal": internal, "protos": protos,
            "denied_dst": denied_dst, "outbound": outbound}


@data_router.delete("/api/vpn-events/clear")
def clear_vpn(sess=Depends(require_admin)):
    audit(sess_user(sess), "clear_vpn")
    with db() as conn:
        conn.execute("DELETE FROM vpn_events")
    return {"status": "ok"}


@data_router.delete("/api/vpn-events/{eid}")
def del_vpn(eid: int, sess=Depends(require_admin)):
    with db() as conn:
        conn.execute("DELETE FROM vpn_events WHERE id=?", (eid,))
    return {"status": "ok"}


@data_router.delete("/api/ad-events/clear")
def clear_ad(sess=Depends(require_admin)):
    audit(sess_user(sess), "clear_ad")
    with db() as conn:
        conn.execute("DELETE FROM ad_events")
    return {"status": "ok"}


@data_router.delete("/api/ad-events/{eid}")
def del_ad(eid: int, sess=Depends(require_admin)):
    with db() as conn:
        conn.execute("DELETE FROM ad_events WHERE id=?", (eid,))
    return {"status": "ok"}


@data_router.post("/api/cleanup")
def manual_cleanup(sess=Depends(require_admin)):
    audit(sess_user(sess), "cleanup")
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = (now - datetime.timedelta(days=settings.retention_days)).strftime("%Y-%m-%d %H:%M:%S")
    alert_cutoff = (now - datetime.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    pb_cutoff = (now - datetime.timedelta(days=settings.playbook_run_days)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        v = conn.execute("DELETE FROM vpn_events WHERE timestamp < ?", (cutoff,)).rowcount
        a = conn.execute("DELETE FROM ad_events WHERE timestamp < ?", (cutoff,)).rowcount
        n = conn.execute("DELETE FROM network_events WHERE timestamp < ?", (cutoff,)).rowcount
        l = conn.execute("DELETE FROM alert_log WHERE sent_at < ?", (alert_cutoff,)).rowcount
        p = conn.execute("DELETE FROM playbook_runs WHERE started_at < ?", (pb_cutoff,)).rowcount
    return {"status": "ok", "deleted": v + a + n + l + p}


@data_router.get("/api/multi-logins")
def get_multi_logins():
    with db() as conn:
        vpn = [dict(r) for r in conn.execute(
            "SELECT MIN(timestamp) ts,username,src_ip FROM vpn_events "
            "WHERE action='login_success' AND src_ip != 'N/A' "
            "GROUP BY username,src_ip"
        ).fetchall()]
        ad = [dict(r) for r in conn.execute(
            "SELECT MIN(timestamp) ts,username,src_ip FROM ad_events "
            "WHERE action IN ('logon_success','kerberos_tgt') "
            "AND src_ip != 'N/A' AND src_ip NOT LIKE '10.0.101.%' "
            "GROUP BY username,src_ip"
        ).fetchall()]

    user_ips = defaultdict(list)
    for row in vpn:
        if _valid(row["username"]):
            user_ips[row["username"]].append({"ts": row["ts"], "ip": row["src_ip"], "source": "VPN"})
    for row in ad:
        if _valid(row["username"]):
            user_ips[row["username"]].append({"ts": row["ts"], "ip": row["src_ip"], "source": "AD"})

    result = []
    for user, ips in user_ips.items():
        unique = {i["ip"] for i in ips}
        if len(unique) >= 2:
            for info in ips:
                result.append({"username": user, "time": info["ts"], "source": info["source"], "ip": info["ip"], "total": len(unique)})
    result.sort(key=lambda x: x["time"], reverse=True)
    return {"events": result}


@data_router.get("/api/triage-status")
def triage_status():
    return {**TRIAGE_STATUS, "auto_triage_enabled": auto_triage_enabled()}


@data_router.post("/api/triage-toggle")
def triage_toggle(body: dict = Body(...), sess=Depends(require_admin)):
    enabled = bool(body.get("enabled", True))
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key,value) VALUES ('auto_triage',?)",
            ("true" if enabled else "false",)
        )
    audit(sess_user(sess), "triage_toggle", str(enabled))
    return {"status": "ok", "enabled": enabled}
