import logging

from fastapi import APIRouter, Body, Depends

from security import require_api_key
from audit import audit
from .auth import require_session, require_admin, sess_user

log = logging.getLogger("telegram")

telegram_router = APIRouter(
    dependencies=[
        Depends(require_api_key),
        Depends(require_session)
    ]
)


@telegram_router.get("/api/telegram/config")
def telegram_config_get(sess=Depends(require_admin)):
    from alerter import _get_telegram_config
    cfg = _get_telegram_config()
    if cfg.get("bot_token"):
        cfg["bot_token"] = cfg["bot_token"][:8] + "..."
    return cfg


@telegram_router.post("/api/telegram/config")
def telegram_config_save(body: dict = Body(...), sess=Depends(require_admin)):
    from alerter import _get_telegram_config, save_telegram_config
    token = body.get("bot_token", "")
    if not token or token.endswith("..."):
        old = _get_telegram_config()
        body["bot_token"] = old.get("bot_token", "")
    cfg = save_telegram_config(body)
    audit(sess_user(sess), "telegram_update")
    return {"status": "ok", "config": cfg}


@telegram_router.post("/api/telegram/test")
def telegram_test(body: dict = Body(...), sess=Depends(require_admin)):
    from alerter import _get_telegram_config, test_telegram
    token = body.get("bot_token", "")
    if not token or token.endswith("..."):
        old = _get_telegram_config()
        body["bot_token"] = old.get("bot_token", "")
    audit(sess_user(sess), "telegram_test")
    return test_telegram(body)