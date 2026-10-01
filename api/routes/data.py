import datetime
import json
import logging
import uuid
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query
from pydantic import BaseModel

from agent import fetch_and_store_logs, run_playbook
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
        r["auth_header"] = mask_token(plain)  # "" if undecryptable
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
    """Run a playbook: LLM analysis over the rule's window (bg task)."""
    with db() as conn:
        row = conn.execute("SELECT name FROM correlation_rules WHERE id=?", (rule_id,)).fetchone()
    if not row:
        raise HTTPException(404, "rule not found")
    audit(sess_user(sess), "playbook_run", row["name"] or rule_id)
    bg.add_task(run_playbook, rule_id)
    return {"status": "started"}


@data_router.post("/api/fetch")
def fetch_all(bg: BackgroundTasks, sess=Depends(require_session)):
    """Manual fetch from all datasources (bg task)."""
    audit(sess_user(sess), "fetch", "all")
    bg.add_task(fetch_and_store_logs, "manual", True)
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
        l = conn.execute("DELETE FROM alert_log WHERE sent_at < ?", (alert_cutoff,)).rowcount
        p = conn.execute("DELETE FROM playbook_runs WHERE started_at < ?", (pb_cutoff,)).rowcount
    return {"status": "ok", "deleted": v + a + l + p}


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