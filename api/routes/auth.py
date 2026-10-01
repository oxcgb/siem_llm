import time
import logging

from fastapi import APIRouter, Body, Depends, Header, HTTPException

from auth import (
    authenticate, create_session,
    get_ldap_config, get_session,
    get_session_ttl, ldap_inspect,
    ldap_search_users,
    public_ldap_config,
    revoke_session,
    save_ldap_config,
    test_ldap_config,
    LDAP_LIB_OK
)
from config import settings
from database import db
from security import require_api_key
from audit import audit

log = logging.getLogger("auth")


def _extract_token(authorization):
    if not authorization:
        return ""
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


async def require_session(authorization: str = Header(default="")):
    """Any authenticated user (ad mode only; no-op in local mode)."""
    if settings.auth_mode != "ad":
        return None
    s = get_session(_extract_token(authorization))
    if not s:
        raise HTTPException(401, "auth required")
    return s


async def require_admin(authorization: str = Header(default="")):
    """Admin only (ad mode only; no-op in local mode)."""
    if settings.auth_mode != "ad":
        return None
    s = get_session(_extract_token(authorization))
    if not s:
        raise HTTPException(401, "auth required")
    if not s["is_admin"]:
        raise HTTPException(403, "admin only")
    return s


def sess_user(sess):
    """Username for audit entries ('local' in local mode)."""
    return sess["username"] if sess else "local"


auth_router = APIRouter(dependencies=[Depends(require_api_key)])


@auth_router.get("/api/auth/mode")
def auth_mode(authorization: str = Header(default="")):
    # NOTE: no require_session here: called before login (no token yet)
    sess = get_session(_extract_token(authorization)) if settings.auth_mode == "ad" else None
    cfg = get_ldap_config()
    return {
        "mode": settings.auth_mode,
        "ldap_enabled": bool(cfg.get("enabled")),
        "ldap_configured": bool(cfg.get("host") and cfg.get("base_dn")),
        "ldap_lib_ok": LDAP_LIB_OK,
        "user": {
            "username": sess["username"],
            "display_name": sess["display_name"],
            "is_admin": bool(sess["is_admin"])
        } if sess else None
    }


@auth_router.post("/api/auth/login")
def auth_login(body: dict = Body(...)):
    method = str(body.get("method", "auto")).lower()
    if method not in ("ad", "local", "auto"):
        method = "auto"
    user, err = authenticate(
        str(body.get("username", "")),
        str(body.get("password", "")),
        method
    )
    if user is None:
        time.sleep(1)
        raise HTTPException(401, err or "wrong")
    audit(user["username"], "login", details=method)
    token, exp = create_session(user["username"], user["display_name"], user["is_admin"])
    log.info("[AUTH] %s %s", user["username"], method)
    return {
        "token": token, "expires": exp,
        "username": user["username"],
        "display_name": user["display_name"],
        "is_admin": user["is_admin"]
    }


@auth_router.post("/api/auth/logout")
def auth_logout(authorization: str = Header(default="")):
    revoke_session(_extract_token(authorization))
    return {"status": "ok"}


@auth_router.get("/api/auth/me")
def auth_me(authorization: str = Header(default="")):
    if settings.auth_mode != "ad":
        return {"user": {"username": "local", "is_admin": True}}
    s = get_session(_extract_token(authorization))
    if not s:
        raise HTTPException(401, "no session")
    return {
        "user": {
            "username": s["username"],
            "display_name": s["display_name"],
            "is_admin": bool(s["is_admin"])
        }
    }


@auth_router.get("/api/auth/ttl")
def auth_ttl_get():
    return {"ttl_hours": get_session_ttl()}


@auth_router.post("/api/auth/ttl")
def auth_ttl_set(body: dict = Body(...), sess=Depends(require_admin)):
    hours = float(body.get("hours", 1))
    if hours not in (0.5, 1, 3, 12):
        raise HTTPException(400, "0.5,1,3,12")
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key,value) VALUES ('session_ttl',?)",
            (str(hours),)
        )
    audit(sess_user(sess), "ttl_update", str(hours))
    return {"status": "ok", "ttl": hours}


@auth_router.get("/api/auth/ldap-config")
def ldap_config_get(sess=Depends(require_admin)):
    return public_ldap_config(get_ldap_config())


@auth_router.post("/api/auth/ldap-config")
def ldap_config_save(body: dict = Body(...), sess=Depends(require_admin)):
    pw = body.get("bind_password", "")
    if not pw or pw == "********":
        old_cfg = get_ldap_config()
        body["bind_password"] = old_cfg.get("bind_password", "")
    saved = save_ldap_config(body)
    audit(sess_user(sess), "ldap_update")
    return {"status": "ok", "config": saved}


@auth_router.post("/api/auth/ldap-test")
def ldap_config_test(body: dict = Body(...), sess=Depends(require_admin)):
    return test_ldap_config(body)


@auth_router.post("/api/auth/ldap-search")
def ldap_search(body: dict = Body(...), sess=Depends(require_admin)):
    q = str(body.get("query", "")).strip()
    if len(q) < 2:
        raise HTTPException(400, "min 2")
    return ldap_search_users(q)


@auth_router.post("/api/auth/ldap-inspect")
def ldap_inspect_user(body: dict = Body(...), sess=Depends(require_admin)):
    u = str(body.get("username", "")).strip()
    if not u:
        raise HTTPException(400, "name")
    return ldap_inspect(u)