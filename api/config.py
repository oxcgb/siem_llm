import ipaddress
import os


def _nets(var, default):
    nets = []
    for n in os.getenv(var, default).split(","):
        n = n.strip()
        if n:
            try:
                nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass
    return nets


class Settings:
    vllm_base_url = os.getenv("VLLM_BASE_URL", "http://vllm:8000/v1")
    vllm_model = os.getenv("VLLM_MODEL", "Qwen/Qwen3-8B-AWQ")
    llm_timeout = int(os.getenv("LLM_TIMEOUT", "180"))

    data_dir = os.getenv("DATA_DIR", "/app/data")

    backend_api_key = os.getenv("BACKEND_API_KEY", "")
    secret_key = os.getenv("SECRET_KEY", "")
    siem_verify = os.getenv("SIEM_VERIFY", "false")
    allow_public_targets = os.getenv("ALLOW_PUBLIC_TARGETS", "false").lower() == "true"

    auth_mode = os.getenv("AUTH_MODE", "local").lower()
    soc_user = os.getenv("SOC_USER", "")
    soc_pass = os.getenv("SOC_PASS", "")
    admin_usernames = {u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()}

    geo_provider = os.getenv("GEO_PROVIDER", "auto").lower()

    off_hours_start = int(os.getenv("OFF_HOURS_START", "20"))
    off_hours_end = int(os.getenv("OFF_HOURS_END", "8"))
    brute_force_threshold = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
    excluded_ad_nets = _nets("EXCLUDED_AD_NETS", "10.0.101.0/24")
    retention_days = int(os.getenv("RETENTION_DAYS", "7"))
    timezone = os.getenv("ANALYSIS_TZ", os.getenv("TZ", "UTC"))

    # Incidents: minimum risk score to be listed (0 = everyone with VPN+AD)
    incident_min_score = int(os.getenv("INCIDENT_MIN_SCORE", "20"))

    # Network alerting: VPN brute-force attempts per hour from one
    # public IP that trigger a Telegram alert
    net_brute_alert = int(os.getenv("NET_BRUTE_ALERT", "50"))

    # P1: alerting
    tg_proxy = os.getenv("TG_PROXY", "")
    alert_cooldown_min = int(os.getenv("ALERT_COOLDOWN_MIN", "120"))

    # P2: fetch pagination, backup, playbook history
    fetch_max_pages = int(os.getenv("FETCH_MAX_PAGES", "4"))
    backup_keep = int(os.getenv("BACKUP_KEEP", "14"))
    playbook_run_days = int(os.getenv("PLAYBOOK_RUN_DAYS", "14"))


settings = Settings()
