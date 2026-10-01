import logging

from fastapi import APIRouter, Body, Depends, Query

from security import require_api_key
from audit import get_entries, cleanup, audit as write_audit
from .auth import require_session, require_admin, sess_user

log = logging.getLogger("audit_routes")

audit_router = APIRouter(
    dependencies=[
        Depends(require_api_key),
        Depends(require_session)
    ]
)


@audit_router.get("/api/audit")
def list_audit(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    username: str = Query("", max_length=50),
    action: str = Query("", max_length=50)
):
    return get_entries(
        limit=limit,
        offset=offset,
        username=username or None,
        action=action or None
    )


@audit_router.post("/api/audit/cleanup")
def audit_cleanup(body: dict = Body(...), sess=Depends(require_admin)):
    days = int(body.get("days", 90))
    deleted = cleanup(days)
    write_audit(sess_user(sess), "audit_cleanup", str(days))
    return {"status": "ok", "deleted": deleted}