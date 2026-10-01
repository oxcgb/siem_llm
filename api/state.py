"""Shared runtime state: job statuses and locks.

Kept separate from main.py so routes/agent can import without
circular dependencies (routes previously imported from main).
"""
import threading

FETCH_STATUS = {
    "status": "idle", "job": None,
    "started_at": None, "finished_at": None,
    "saved": 0, "message": ""
}

TRIAGE_STATUS = {
    "status": "idle",
    "analyzed": 0,
    "alerts_sent": 0,
    "message": ""
}

REPORT_STATUS = {
    "status": "idle", "rule_id": None, "rule_name": "",
    "run_id": None,
    "started_at": None, "finished_at": None,
    "total": 0, "analyzed": 0, "message": ""
}

fetch_lock = threading.Lock()
triage_lock = threading.Lock()
report_lock = threading.Lock()


def auto_triage_enabled():
    """Auto-triage toggle (settings.auto_triage; default: enabled)."""
    from database import db
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='auto_triage'").fetchone()
    if not row:
        return True
    return row["value"].strip().lower() == "true"