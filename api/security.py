import base64
import hashlib
import ipaddress
import logging
import os
import secrets
import socket
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from config import settings

log = logging.getLogger("security")

_fernet = None
_tls_warned = False


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    raw = settings.secret_key
    if not raw:
        keyfile = os.path.join(settings.data_dir, ".secret_key")
        os.makedirs(settings.data_dir, exist_ok=True)
        if os.path.exists(keyfile):
            with open(keyfile) as f:
                raw = f.read().strip()
        else:
            raw = secrets.token_hex(32)
            with open(keyfile, "w") as f:
                f.write(raw)
            os.chmod(keyfile, 0o600)
            log.warning("SECRET_KEY not set: generated %s", keyfile)
    _fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()))
    return _fernet


def encrypt_secret(plain):
    if not plain:
        return ""
    return _get_fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token):
    if not token:
        return ""
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        log.error(
            "decrypt_secret failed (ciphertext prefix=%r): SECRET_KEY rotated or DB corrupted. "
            "Returning empty - re-enter the secret in Settings.",
            token[:12],
        )
        return ""


def mask_token(plain):
    if not plain:
        return ""
    return plain[:6] + "..." if len(plain) <= 12 else plain[:6] + "..." + plain[-4:]


def tls_verify():
    global _tls_warned
    v = str(settings.siem_verify).strip().lower()
    if v in ("1", "true", "yes"):
        return True
    if v in ("0", "false", "no", ""):
        if not _tls_warned:
            log.warning("SIEM_VERIFY=false: TLS disabled (dev only)")
            _tls_warned = True
        return False
    return str(settings.siem_verify).strip()


def _validate_url(url):
    """Structural URL check: http(s) scheme + non-empty host."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        return p
    except Exception:
        return None


def is_allowed_target(url):
    """Cheap structural check (no DNS). Used for form validation.

    Full SSRF protection (resolve once -> pin the IP) is done by
    resolve_allowed_target at request time.
    """
    p = _validate_url(url)
    return p is not None


def resolve_allowed_target(url):
    """Validate a target AND pin its IP (SSRF/DNS-rebinding safe).

    Resolves the hostname ONCE, checks the address against the allow
    policy (private/loopback unless ALLOW_PUBLIC_TARGETS), and returns
    the URL rewritten to the pinned IP, so the subsequent HTTP request
    cannot be re-resolved to a different address by an attacker
    controlling DNS. Host header is not restored (SIEM endpoints do
    not rely on it); returns None when the target is not allowed or
    unresolvable. IPv6 addresses are bracketed in the rewritten URL.
    """
    p = _validate_url(url)
    if p is None:
        return None
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
        addrs = [i[4][0] for i in infos]
    except Exception:
        return None
    if not addrs:
        return None

    ok = False
    pinned = None
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        allowed = bool(ip.is_private or ip.is_loopback) or settings.allow_public_targets
        if allowed:
            pinned = a
            ok = True
            break
    if not ok or pinned is None:
        return None

    netloc = f"[{pinned}]" if ":" in pinned else pinned
    if p.port:
        netloc += f":{p.port}"
    return f"{p.scheme}://{netloc}{p.path or '/'}" + (f"?{p.query}" if p.query else "")


_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(key=Security(_api_key_header)):
    if not settings.backend_api_key or key != settings.backend_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")