import datetime
import logging

from database import db

log = logging.getLogger("audit")

UTC = datetime.timezone.utc
FMT = "%Y-%m-%d %H:%M:%S"


def _now():
    return (
        datetime.datetime
        .now(UTC)
        .strftime(FMT)
    )


def audit(
    username,
    action,
    target="",
    details=""
):
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO "
                "audit_log "
                "(timestamp, "
                "username, action, "
                "target, details)"
                " VALUES "
                "(?,?,?,?,?)",
                (
                    _now(),
                    username,
                    action,
                    target[:200],
                    details[:500]
                )
            )
        log.info(
            "[AUDIT] %s %s %s",
            username, action,
            target
        )
    except Exception as e:
        log.error(
            "[AUDIT] fail: %s",
            e
        )


def get_entries(
    limit=100,
    offset=0,
    username=None,
    action=None
):
    where = []
    params = []

    if username:
        where.append(
            "username LIKE ?"
        )
        params.append(
            f"%{username}%"
        )

    if action:
        where.append(
            "action LIKE ?"
        )
        params.append(
            f"%{action}%"
        )

    w = (
        "WHERE "
        + " AND ".join(where)
        if where else ""
    )

    with db() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) "
            f"c FROM audit_log"
            f" {w}",
            params
        ).fetchone()["c"]

        rows = conn.execute(
            f"SELECT * FROM "
            f"audit_log {w} "
            f"ORDER BY id DESC "
            f"LIMIT ? OFFSET ?",
            params + [
                limit, offset
            ]
        ).fetchall()

    return {
        "entries": [
            dict(r)
            for r in rows
        ],
        "total": total
    }


def cleanup(days=90):
    cutoff = (
        datetime.datetime
        .now(UTC)
        - datetime
        .timedelta(days=days)
    ).strftime(FMT)

    with db() as conn:
        deleted = conn.execute(
            "DELETE FROM "
            "audit_log "
            "WHERE timestamp "
            "< ?",
            (cutoff,)
        ).rowcount

    return deleted
