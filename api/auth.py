import datetime
import hmac
import json
import logging
import secrets

from config import settings
from database import db
from security import encrypt_secret, decrypt_secret

log = logging.getLogger("auth")

try:
    from ldap3 import Server, Connection, SUBTREE
    from ldap3.utils.conv import escape_filter_chars
    LDAP_LIB_OK = True
except ImportError:
    LDAP_LIB_OK = False
    log.warning("ldap3 not installed")

UTC = datetime.timezone.utc
FMT = "%Y-%m-%d %H:%M:%S"

DEFAULT_LDAP_CONFIG = {
    "enabled": False, "host": "", "port": 389,
    "use_ssl": False, "base_dn": "", "bind_dn": "",
    "bind_password": "",
    "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
    "admin_group": "", "admin_usernames": ""
}


def _clean_username(username):
    u = (username or "").strip()
    if "\\" in u:
        u = u.split("\\")[-1].strip()
    if "@" in u:
        u = u.split("@")[0].strip()
    return u


def get_ldap_config():
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='ldap_config'").fetchone()
    cfg = dict(DEFAULT_LDAP_CONFIG)
    if row and row["value"]:
        try:
            cfg.update(json.loads(row["value"]))
        except Exception:
            pass
    return cfg


def public_ldap_config(cfg):
    out = dict(cfg)
    out["bind_password"] = ""
    out["has_password"] = bool(cfg.get("bind_password"))
    return out


def save_ldap_config(cfg):
    stored = dict(DEFAULT_LDAP_CONFIG)
    for k in DEFAULT_LDAP_CONFIG:
        if k in cfg:
            stored[k] = cfg[k]
    pw = str(cfg.get("bind_password") or "").strip()
    if pw and pw != "********":
        stored["bind_password"] = encrypt_secret(pw)
    else:
        stored["bind_password"] = get_ldap_config().get("bind_password", "")
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('ldap_config', ?)", (json.dumps(stored),))
    return public_ldap_config(stored)


def get_session_ttl():
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='session_ttl'").fetchone()
    if row:
        try:
            return float(row["value"])
        except (ValueError, TypeError):
            pass
    return 1


def _ldap_server(cfg):
    return Server(str(cfg.get("host") or ""), port=int(cfg.get("port") or 389),
                  use_ssl=bool(cfg.get("use_ssl")), connect_timeout=5)


def _is_admin(username, groups, cfg):
    if username.lower() in settings.admin_usernames:
        return True
    admins = {u.strip().lower() for u in str(cfg.get("admin_usernames") or "").split(",") if u.strip()}
    if username.lower() in admins:
        return True
    grp = str(cfg.get("admin_group") or "").strip().lower()
    if grp:
        for g in groups:
            if grp in str(g).lower():
                return True
    return False


def _service_connect(cfg):
    if not LDAP_LIB_OK:
        return None, "ldap3 not installed"
    if not cfg.get("host") or not cfg.get("base_dn"):
        return None, "not configured"
    bind_pw = decrypt_secret(cfg.get("bind_password") or "")
    if (cfg.get("bind_dn") or "") and not bind_pw:
        # bind_dn set but password unreadable: refuse instead of
        # silently falling back to anonymous bind (empty pw = anonymous)
        return None, "bind password unavailable (SECRET_KEY rotated? re-save LDAP config)"
    server = _ldap_server(cfg)
    try:
        conn = Connection(server, user=cfg.get("bind_dn") or None,
                          password=bind_pw or None, read_only=True,
                          auto_bind=False, receive_timeout=30)
    except Exception as e:
        return None, "conn: " + str(e)
    try:
        if not conn.bind():
            return None, "bind failed"
    except Exception as e:
        return None, "bind: " + str(e)
    return conn, None


def _check_local(username, password):
    username = _clean_username(username)
    if not username or not password:
        return None, "empty"
    if settings.soc_user and settings.soc_pass:
        if username == _clean_username(settings.soc_user) and hmac.compare_digest(
                password.encode(), settings.soc_pass.encode()):
            return {"username": settings.soc_user, "display_name": "Local Admin",
                    "is_admin": True, "source": "local"}, None
    return None, "wrong local"


def _check_ad(username, password):
    username = _clean_username(username)
    if not username or not password:
        return None, "empty"
    cfg = get_ldap_config()
    if not cfg.get("enabled"):
        return None, "AD disabled"

    conn, err = _service_connect(cfg)
    if conn is None:
        return None, err
    try:
        flt = str(cfg.get("user_filter") or DEFAULT_LDAP_CONFIG["user_filter"]).replace(
            "{username}", escape_filter_chars(username))
        conn.search(str(cfg["base_dn"]), flt, SUBTREE,
                    attributes=["cn", "displayName", "memberOf", "sAMAccountName"])
        if not conn.entries:
            return None, "not found"
        entry = conn.entries[0]
        user_dn = entry.entry_dn
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    server = _ldap_server(cfg)
    try:
        uconn = Connection(server, user=user_dn, password=password,
                           read_only=True, auto_bind=False, receive_timeout=30)
    except Exception as e:
        return None, "conn: " + str(e)
    try:
        if not uconn.bind():
            return None, "wrong password"
    finally:
        try:
            uconn.unbind()
        except Exception:
            pass

    groups, display = [], username
    try:
        if "memberOf" in entry:
            groups = [str(g) for g in entry.memberOf.values]
        if "displayName" in entry and entry.displayName.values:
            display = str(entry.displayName.values[0])
        elif "cn" in entry and entry.cn.values:
            display = str(entry.cn.values[0])
    except Exception:
        pass

    return {"username": username, "display_name": display,
            "is_admin": _is_admin(username, groups, cfg), "source": "ad"}, None


def authenticate(username, password, method="auto"):
    if method == "local":
        return _check_local(username, password)
    if method == "ad":
        return _check_ad(username, password)
    user, err = _check_local(username, password)
    if user:
        return user, None
    user, err2 = _check_ad(username, password)
    if user:
        return user, None
    return None, err2 or err


def test_ldap_config(cfg):
    if not LDAP_LIB_OK:
        return {"ok": False, "message": "ldap3 not installed"}
    if not cfg.get("host") or not cfg.get("base_dn"):
        return {"ok": False, "message": "host + base_dn required"}
    stored = get_ldap_config()
    pw = str(cfg.get("bind_password") or "").strip()
    test_cfg = dict(cfg)
    if pw and pw != "********":
        test_cfg["bind_password"] = pw
    else:
        test_cfg["bind_password"] = stored.get("bind_password", "")
    conn, err = _service_connect(test_cfg)
    if conn is None:
        return {"ok": False, "message": err}
    try:
        probe = _clean_username(str(cfg.get("admin_usernames") or "").split(",")[0]
                                or settings.soc_user or "administrator")
        flt = str(cfg.get("user_filter") or DEFAULT_LDAP_CONFIG["user_filter"]).replace(
            "{username}", escape_filter_chars(probe))
        conn.search(str(cfg["base_dn"]), flt, SUBTREE, attributes=["cn"])
        return {"ok": True, "message": "bind OK; " + str(len(conn.entries)) + " match"}
    except Exception as e:
        return {"ok": False, "message": str(e)}
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def ldap_search_users(fragment, limit=10):
    fragment = _clean_username(fragment)
    if not fragment or len(fragment) < 2:
        return {"ok": False, "message": "min 2"}
    cfg = get_ldap_config()
    conn, err = _service_connect(cfg)
    if conn is None:
        return {"ok": False, "message": err}
    users = []
    try:
        esc = escape_filter_chars(fragment)
        flt = "(|(sAMAccountName=*%s*)(cn=*%s*)(displayName=*%s*)(userPrincipalName=%s*))" % (esc, esc, esc, esc)
        conn.search(str(cfg["base_dn"]), flt, SUBTREE,
                    attributes=["sAMAccountName", "cn", "displayName", "userPrincipalName", "memberOf"],
                    size_limit=limit)
        for e in conn.entries[:limit]:
            sam = e.sAMAccountName.value if "sAMAccountName" in e else ""
            uname = sam or (str(e.cn.values[0]) if "cn" in e and e.cn.values else "")
            groups = [str(g) for g in e.memberOf.values] if "memberOf" in e else []
            disp = str(e.displayName.values[0]) if "displayName" in e and e.displayName.values else ""
            users.append({
                "username": uname, "display_name": disp,
                "dn": e.entry_dn,
                "upn": e.userPrincipalName.value if "userPrincipalName" in e else "",
                "groups_count": len(groups),
                "will_be_admin": _is_admin(uname, groups, cfg)
            })
        return {"ok": True, "users": users, "found": len(users)}
    except Exception as e:
        return {"ok": False, "message": "search: " + str(e)}
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def ldap_inspect(username):
    username = _clean_username(username)
    cfg = get_ldap_config()
    conn, err = _service_connect(cfg)
    if conn is None:
        return {"ok": False, "message": err}
    try:
        flt = str(cfg.get("user_filter") or DEFAULT_LDAP_CONFIG["user_filter"]).replace(
            "{username}", escape_filter_chars(username))
        conn.search(str(cfg["base_dn"]), flt, SUBTREE,
                    attributes=["sAMAccountName", "cn", "displayName", "userPrincipalName", "memberOf"])
        if not conn.entries:
            return {"ok": True, "found": False, "message": "not found"}
        e = conn.entries[0]
        groups = [str(g) for g in e.memberOf.values] if "memberOf" in e else []
        return {
            "ok": True, "found": True,
            "username": e.sAMAccountName.value if "sAMAccountName" in e else username,
            "display_name": str(e.displayName.values[0]) if "displayName" in e and e.displayName.values else "",
            "dn": e.entry_dn,
            "upn": e.userPrincipalName.value if "userPrincipalName" in e else "",
            "groups": groups,
            "will_be_admin": _is_admin(username, groups, cfg)
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def create_session(username, display_name, is_admin):
    token = secrets.token_urlsafe(32)
    now = datetime.datetime.now(UTC)
    ttl = get_session_ttl()
    exp = now + datetime.timedelta(hours=ttl)
    with db() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now.strftime(FMT),))
        conn.execute(
            "INSERT INTO auth_sessions (token,username,display_name,is_admin,created_at,expires_at) VALUES (?,?,?,?,?,?)",
            (token, username, display_name or username, int(bool(is_admin)),
             now.strftime(FMT), exp.strftime(FMT)))
    return token, exp.strftime(FMT)


def get_session(token):
    if not token:
        return None
    now = datetime.datetime.now(UTC)
    now_s = now.strftime(FMT)
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM auth_sessions WHERE token=? AND expires_at >= ?",
            (token, now_s)).fetchone()
        if not row:
            return None
        sess = dict(row)
        # Renew only when < 25% of TTL remains (avoids a write per request)
        ttl = get_session_ttl()
        try:
            exp = datetime.datetime.strptime(sess["expires_at"], FMT).replace(tzinfo=UTC)
            if (exp - now) < datetime.timedelta(hours=ttl * 0.25):
                new_exp = now + datetime.timedelta(hours=ttl)
                conn.execute("UPDATE auth_sessions SET expires_at=? WHERE token=?",
                             (new_exp.strftime(FMT), token))
        except (ValueError, TypeError):
            pass
        return sess


def revoke_session(token):
    if token:
        with db() as conn:
            conn.execute("DELETE FROM auth_sessions WHERE token=?", (token,))