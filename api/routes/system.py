import os
import logging
import subprocess

import httpx
import psutil
from fastapi import APIRouter, Body, Depends, HTTPException

from database import db, backup_db
from security import require_api_key
from config import settings
from audit import audit
from .auth import require_session, require_admin, sess_user

log = logging.getLogger("system")

try:
    import pynvml
    pynvml.nvmlInit()
    NVML_OK = True
except Exception:
    NVML_OK = False

public_router = APIRouter()
system_router = APIRouter(
    dependencies=[
        Depends(require_api_key),
        Depends(require_session)
    ]
)


@public_router.get("/api/health")
def health():
    return {"status": "ok"}


@public_router.get("/api/config")
def public_config():
    """Runtime UI configuration (no secrets): display timezone, version,
    detection thresholds. The frontend reads this instead of baked-in
    VITE_DISPLAY_TZ, so a timezone change no longer requires a rebuild."""
    return {
        "version": "1.5.0",
        "display_tz": settings.timezone,
        "off_hours_start": settings.off_hours_start,
        "off_hours_end": settings.off_hours_end,
        "brute_force_threshold": settings.brute_force_threshold,
        "incident_min_score": settings.incident_min_score,
    }


@system_router.get("/api/golden-status")
def golden_status(sess=Depends(require_session)):
    """Run the golden test and report the real score (not a hardcoded
    '4/4'). Reads the golden set only; verdicts are not persisted."""
    try:
        out = subprocess.run(
            ["python", "/app/golden_test.py"],
            capture_output=True, text=True, timeout=300
        ).stdout.strip().splitlines()
        score = next((l for l in reversed(out) if l.startswith("Score:")), "?")
        return {"ok": True, "score": score}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@system_router.get("/api/system-stats")
def system_stats():
    cpu = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory()
    gpu_u, gpu_t = 0.0, 0.0
    if NVML_OK:
        try:
            h = pynvml.nvmlDeviceGetHandleByIndex(0)
            info = pynvml.nvmlDeviceGetMemoryInfo(h)
            gpu_u = info.used / (1024 ** 3)
            gpu_t = info.total / (1024 ** 3)
        except Exception:
            pass
    return {
        "cpu": round(cpu, 1),
        "ram_used": round(ram.used / (1024 ** 3), 1),
        "ram_total": round(ram.total / (1024 ** 3), 1),
        "gpu_used": round(gpu_u, 1),
        "gpu_total": round(gpu_t, 1)
    }


@system_router.get("/api/vllm/info")
def vllm_info():
    info = {
        "healthy": False, "version": "?",
        "model": "?", "gpu": {},
        "tag": os.getenv("VLLM_IMAGE_TAG", "v0.11.0")
    }
    base = settings.vllm_base_url.replace("/v1", "")
    try:
        r = httpx.get(base + "/health", timeout=5.0)
        info["healthy"] = r.status_code == 200
    except Exception:
        pass
    try:
        r = httpx.get(base + "/version", timeout=5.0)
        if r.status_code == 200:
            info["version"] = r.json().get("version", "?")
    except Exception:
        pass
    try:
        r = httpx.get(settings.vllm_base_url + "/models", timeout=5.0)
        if r.status_code == 200:
            models = r.json().get("data", [])
            if models:
                info["model"] = models[0].get("id", "?")
    except Exception:
        pass
    if NVML_OK:
        try:
            h = pynvml.nvmlDeviceGetHandleByIndex(0)
            name = pynvml.nvmlDeviceGetName(h)
            mem = pynvml.nvmlDeviceGetMemoryInfo(h)
            info["gpu"] = {
                "name": str(name),
                "used": round(mem.used / (1024 ** 3), 1),
                "total": round(mem.total / (1024 ** 3), 1)
            }
        except Exception:
            pass
    return info


@system_router.post("/api/vllm/check-update")
def vllm_check_update():
    import re
    current = os.getenv("VLLM_IMAGE_TAG", "v0.11.0").lstrip("v")
    m = re.search(r"(\d+\.\d+\.\d+)", current)
    if m:
        current = m.group(1)

    tags = []
    try:
        r = httpx.get(
            "https://hub.docker.com/v2/repositories/vllm/vllm-openai/tags/",
            params={"page_size": 100},
            timeout=15.0
        )
        if r.status_code == 200:
            for tag in r.json().get("results", []):
                name = tag.get("name", "")
                if re.match(r"^v\d+\.\d+\.\d+$", name):
                    tags.append({
                        "v": name,
                        "date": tag.get("last_updated", "")[:10]
                    })
    except Exception as e:
        return {"ok": False, "current": "v" + current, "error": str(e)}

    if not tags:
        return {"ok": False, "current": "v" + current, "error": "no tags found"}

    cur = [int(x) for x in current.split(".")]
    updates = []
    for t in tags:
        v = t["v"].lstrip("v")
        vp = [int(x) for x in v.split(".")]
        if vp > cur:
            updates.append(t)

    return {
        "ok": True,
        "current": "v" + current,
        "up_to_date": len(updates) == 0,
        "latest": tags[0]["v"] if tags else "?",
        "updates": updates[:5]
    }


@system_router.get("/api/model/check-update")
def model_check_update():
    import httpx
    current = os.getenv("VLLM_MODEL", "Qwen/Qwen3-8B-AWQ")
    repo = current.split("/")[0]
    name = current.split("/")[1] if "/" in current else current

    models = []
    try:
        r = httpx.get(
            "https://huggingface.co/api/models?search=" + name + "&limit=10&sort=downloads&direction=-1",
            timeout=10.0
        )
        if r.status_code == 200:
            for m in r.json():
                model_id = m.get("modelId", "")
                if repo in model_id:
                    models.append({
                        "model": model_id,
                        "downloads": m.get("downloads", 0),
                        "updated": m.get("lastModified", "")[:10]
                    })
    except Exception as e:
        return {"ok": False, "current": current, "error": str(e)}

    return {"ok": True, "current": current, "models": models[:5], "repo": repo}


@system_router.get("/api/stats/summary")
def stats_summary():
    with db() as conn:
        return {
            "datasources": conn.execute("SELECT COUNT(*) c FROM datasources").fetchone()["c"],
            "rules": conn.execute("SELECT COUNT(*) c FROM correlation_rules").fetchone()["c"],
            "vpn_events": conn.execute("SELECT COUNT(*) c FROM vpn_events").fetchone()["c"],
            "ad_events": conn.execute("SELECT COUNT(*) c FROM ad_events").fetchone()["c"],
            "recent_vpn": [
                dict(r) for r in conn.execute(
                    "SELECT id,timestamp,username,src_ip,action "
                    "FROM vpn_events WHERE action != 'unknown' AND username != 'N/A' "
                    "ORDER BY timestamp DESC LIMIT 10"
                ).fetchall()
            ]
        }


@system_router.post("/api/system/backup")
def run_backup(sess=Depends(require_admin)):
    """Manual DB backup (VACUUM INTO data/backups/)."""
    try:
        path = backup_db()
        audit(sess_user(sess), "backup", path)
        return {"status": "ok", "path": path}
    except Exception as e:
        log.error("[BACKUP] manual failed: %s", e)
        raise HTTPException(500, str(e))


@system_router.get("/api/settings/prompt")
def get_prompt(sess=Depends(require_admin)):
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='ai_triage_prompt'").fetchone()
    return {"prompt": row["value"] if row else ""}


@system_router.post("/api/settings/prompt")
def set_prompt(body: dict = Body(...), sess=Depends(require_admin)):
    prompt = body.get("prompt", "")
    if "{logs_str}" not in prompt:
        raise HTTPException(400, "logs_str required")
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('ai_triage_prompt', ?)",
            (prompt,)
        )
    audit(sess_user(sess), "prompt_update")
    return {"status": "ok"}

# ------------------------------------------------------------------ UEBA tab
# Settings -> UEBA: runtime configuration of the behaviour engine in
# incidents.py. Knobs are stored in the settings table (ueba_* keys),
# layered above the UEBA_* environment variables, and are folded into
# the live config once per build cycle (refresh_ueba_config). Editing
# them needs neither a rebuild nor a container restart.


@system_router.get("/api/settings/ueba")
def get_ueba(sess=Depends(require_admin)):
    """Effective UEBA config, active overrides and baseline health."""
    from incidents import ueba_status
    return ueba_status()


@system_router.post("/api/settings/ueba")
def set_ueba(body: dict = Body(...), sess=Depends(require_admin)):
    """Partial update of UEBA knobs (only the provided keys change).
    'enabled' maps to the runtime kill-switch key 'ueba_enabled'."""
    from incidents import validate_ueba_overrides, ueba_status
    clean, errors = validate_ueba_overrides(body)
    if errors:
        raise HTTPException(400, "; ".join(errors))
    with db() as conn:
        for key, val in clean.items():
            setting = "ueba_enabled" if key == "enabled" else f"ueba_{key}"
            stored = "true" if val is True else "false" if val is False else str(val)
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (setting, stored)
            )
    audit(sess_user(sess), "ueba_update",
          details=",".join(sorted(clean))[:200])
    return ueba_status()


@system_router.delete("/api/settings/ueba")
def reset_ueba(sess=Depends(require_admin)):
    """Drop every ueba_* override (including the runtime switch):
    back to environment / built-in defaults."""
    from incidents import ueba_status
    with db() as conn:
        conn.execute("DELETE FROM settings WHERE key LIKE 'ueba_%'")
    audit(sess_user(sess), "ueba_reset")
    return ueba_status()


@system_router.post("/api/settings/ueba/rebuild")
def rebuild_ueba(sess=Depends(require_admin)):
    """Force a baseline rebuild now (otherwise it happens lazily when
    the profiles are older than UEBA_BASELINE_TTL_HOURS)."""
    from incidents import rebuild_baselines, ueba_status
    ok = rebuild_baselines(force=True)
    status = ueba_status()
    status["rebuild"] = "done" if ok else "skipped"
    audit(sess_user(sess), "ueba_rebuild")
    return status
