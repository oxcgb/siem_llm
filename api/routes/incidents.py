import logging

from fastapi import APIRouter, Body, Depends, HTTPException

from agent import analyze_incidents_with_llm
from incidents import (
    WATCHLISTS,
    add_watchlist,
    build_incidents,
    delete_triage,
    list_watchlists,
    remove_watchlist,
    save_triage,
    triage_stats,
)
from security import require_api_key
from audit import audit
from .auth import require_session, require_admin, sess_user

log = logging.getLogger("incidents")


incident_router = APIRouter(
    dependencies=[
        Depends(require_api_key),
        Depends(require_session)
    ]
)


def _valid(u):
    return bool(u) and u not in ("N/A", "ERROR", "*****", "")


@incident_router.get("/api/incidents")
def get_incidents():
    return {"incidents": build_incidents()}


# ------------------------------------------------------------------ watchlists
# v1.6.2: curated user lists that change how the UEBA engine treats a
# user.
#   elevated - never suppress rule points for this user (VIPs, departing
#              employees, accounts under investigation);
#   benign   - service/monitoring accounts whose noise rules are always
#              suppressed (absolutes still alert).
# Effects apply while UEBA is enabled; management is admin-only, every
# change is audited.


@incident_router.get("/api/watchlists")
def get_watchlists(sess=Depends(require_admin)):
    return {"watchlists": list_watchlists()}


@incident_router.post("/api/watchlists")
def post_watchlist(body: dict = Body(...), sess=Depends(require_admin)):
    username = str(body.get("username") or "").strip()
    list_name = str(body.get("list_name") or "").strip()
    note = str(body.get("note") or "").strip()
    if not _valid(username) or not 1 <= len(username) <= 64:
        raise HTTPException(400, "username: required (1-64 chars)")
    if list_name not in WATCHLISTS:
        raise HTTPException(400, "list_name must be one of: " + ", ".join(WATCHLISTS))
    add_watchlist(username, list_name, note, sess_user(sess))
    audit(sess_user(sess), "watchlist_add", username, list_name)
    return {"watchlists": list_watchlists()}


@incident_router.delete("/api/watchlists/{row_id}")
def del_watchlist(row_id: int, sess=Depends(require_admin)):
    if not remove_watchlist(row_id):
        raise HTTPException(404, "watchlist entry not found")
    audit(sess_user(sess), "watchlist_remove", str(row_id))
    return {"watchlists": list_watchlists()}


# ------------------------------------------------------------------ triage
# v1.6.2: analyst verdicts per (user, UTC-day of the incident's last
# event). 'fp' incidents drop out of the automatic list (and stop
# alerting); 'tp' incidents stay visible with the verdict attached.
# Verdicts power the detection-quality metrics (precision, per-rule).


@incident_router.post("/api/incidents/triage")
def post_triage(body: dict = Body(...), sess=Depends(require_admin)):
    username = str(body.get("username") or "").strip()
    date = str(body.get("date") or "").strip()
    status = str(body.get("status") or "").strip().lower()
    reason = str(body.get("reason") or "").strip()
    if not _valid(username):
        raise HTTPException(400, "username required")
    if len(date) != 10:
        raise HTTPException(
            400, "date required (YYYY-MM-DD - the incident's last-seen day)")
    if status not in ("tp", "fp"):
        raise HTTPException(400, "status must be 'tp' or 'fp'")
    rules = body.get("signals")
    if not isinstance(rules, list):
        rules = []
    save_triage(username, date, status, reason, sess_user(sess),
                [str(r)[:40] for r in rules])
    audit(sess_user(sess), "triage_set", username, "%s %s" % (status, date))
    return triage_stats()


@incident_router.delete("/api/incidents/triage")
def del_triage(username: str, date: str, sess=Depends(require_admin)):
    if not delete_triage(username.strip(), date.strip()):
        raise HTTPException(404, "no triage entry for that user/day")
    audit(sess_user(sess), "triage_reopen", username.strip(), date.strip())
    return {"ok": True}


@incident_router.get("/api/incidents/triage/stats")
def get_triage_stats(sess=Depends(require_admin)):
    return triage_stats()


@incident_router.post("/api/incidents/analyze")
def analyze_incidents(body: dict = Body(...), sess=Depends(require_session)):
    names = body.get("usernames")
    if not names and isinstance(body.get("incidents"), list):
        names = [i.get("username") for i in body["incidents"] if i.get("username")]
    names = {u for u in (names or []) if _valid(u)}
    if not names:
        return {"incidents": []}

    incidents = build_incidents(names)
    if not incidents:
        return {"incidents": []}

    audit(sess_user(sess), "triage", str(len(names)) + " users")
    results = analyze_incidents_with_llm(incidents)

    for inc in incidents:
        r = results.get(inc["username"], {})
        inc["ai_verdict"] = r.get("ai_verdict", "not_analyzed")
        inc["ai_reason"] = r.get("ai_reason", "N/A")

    try:
        from alerter import send_alert
        send_alert(incidents)
    except Exception as e:
        log.error("[ALERT] %s", e)

    return {"incidents": incidents}
