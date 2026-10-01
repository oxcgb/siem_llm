import datetime
import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import init_db
from state import TRIAGE_STATUS, triage_lock, auto_triage_enabled
from routes import (
    auth_router,
    data_router,
    incident_router,
    system_router,
    public_router,
    telegram_router,
    audit_router
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("main")

scheduler = BackgroundScheduler()


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def auto_triage():
    from incidents import build_incidents
    from agent import analyze_incidents_with_llm

    with triage_lock:
        if TRIAGE_STATUS["status"] == "running":
            return
        TRIAGE_STATUS.update(status="running", message="")

    try:
        incidents = build_incidents()
        if not incidents:
            TRIAGE_STATUS.update(status="done", analyzed=0, total=0, message="none")
            return

        fresh = [i for i in incidents if i.get("ai_verdict") == "not_analyzed"]
        if not fresh:
            TRIAGE_STATUS.update(status="done", analyzed=0, total=len(incidents), message="cached")
            return

        results = analyze_incidents_with_llm(fresh)

        for inc in fresh:
            r = results.get(inc["username"], {})
            if r:
                inc["ai_verdict"] = r.get("ai_verdict", "not_analyzed")
                inc["ai_reason"] = r.get("ai_reason", "")

        try:
            from alerter import send_alert
            sent = send_alert(fresh)
            TRIAGE_STATUS.update(alerts_sent=sent)
        except Exception as e:
            log.error("[ALERT] %s", e)

        TRIAGE_STATUS.update(
            status="done",
            analyzed=len(results),
            total=len(incidents),
            last_run=utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            message="done " + str(len(results)) + "/" + str(len(fresh))
        )
    except Exception as e:
        TRIAGE_STATUS.update(status="error", message=str(e))
        log.error("[TRIAGE] %s", e)


def auto_cycle():
    from agent import fetch_and_store_logs
    saved = fetch_and_store_logs("system_auto", manual=False)
    # Fetch continues regardless; the flag gates only AI analysis + alerts
    if saved > 0 and auto_triage_enabled():
        auto_triage()


def retention_job():
    from database import db
    from datetime import timedelta
    cutoff = (utcnow() - timedelta(days=settings.retention_days)).strftime("%Y-%m-%d %H:%M:%S")
    alert_cutoff = (utcnow() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    pb_cutoff = (utcnow() - timedelta(days=settings.playbook_run_days)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        v = conn.execute("DELETE FROM vpn_events WHERE timestamp < ?", (cutoff,)).rowcount
        a = conn.execute("DELETE FROM ad_events WHERE timestamp < ?", (cutoff,)).rowcount
        l = conn.execute("DELETE FROM alert_log WHERE sent_at < ?", (alert_cutoff,)).rowcount
        p = conn.execute("DELETE FROM playbook_runs WHERE started_at < ?", (pb_cutoff,)).rowcount
    if v or a or l or p:
        log.info("[RET] vpn=%d ad=%d alert_log=%d playbook_runs=%d", v, a, l, p)


def backup_job():
    from database import backup_db
    try:
        path = backup_db()
        log.info("[BACKUP] %s", path)
    except Exception as e:
        log.error("[BACKUP] %s", e)


def audit_cleanup_job():
    from audit import cleanup
    try:
        deleted = cleanup(days=90)
        if deleted:
            log.info("[AUDIT] cleaned %d entries", deleted)
    except Exception as e:
        log.error("[AUDIT] cleanup failed: %s", e)


@asynccontextmanager
async def lifespan(app):
    init_db()
    scheduler.add_job(auto_cycle, "interval", minutes=5, id="auto_fetch", replace_existing=True, max_instances=1)
    scheduler.add_job(retention_job, "cron", hour=4, minute=0, id="retention", replace_existing=True)
    scheduler.add_job(backup_job, "cron", hour=3, minute=0, id="backup", replace_existing=True)
    scheduler.add_job(audit_cleanup_job, "cron", hour=5, minute=0, id="audit_cleanup", replace_existing=True)
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SOC LLM", version="1.5.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(public_router)
app.include_router(auth_router)
app.include_router(data_router)
app.include_router(incident_router)
app.include_router(system_router)
app.include_router(telegram_router)
app.include_router(audit_router)