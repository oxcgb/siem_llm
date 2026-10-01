import logging

from fastapi import APIRouter, Body, Depends

from agent import analyze_incidents_with_llm
from incidents import build_incidents
from security import require_api_key
from audit import audit
from .auth import require_session, sess_user

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