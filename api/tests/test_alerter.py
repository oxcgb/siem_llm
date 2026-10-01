"""Alert dedup / cooldown / formatting tests."""
import alerter


def _inc(user, last_seen, severity="medium", score=50):
    return {"username": user, "last_seen": last_seen, "severity": severity,
            "risk_score": score, "ai_verdict": "suspicious", "ai_reason": "x",
            "off_hours": True, "multi_geo": False, "ad_without_vpn": False,
            "failed_logins": 2, "vpn_count": 1, "ad_count": 1, "vpn_geo": ""}


class TestAlertKey:
    def test_key_changes_with_last_seen(self):
        assert alerter._alert_key(_inc("u", "t1")) != alerter._alert_key(_inc("u", "t2"))

    def test_key_changes_with_severity(self):
        assert alerter._alert_key(_inc("u", "t1", "low")) != alerter._alert_key(_inc("u", "t1", "high"))

    def test_key_same_for_identical_state(self):
        assert alerter._alert_key(_inc("u", "t1")) == alerter._alert_key(_inc("u", "t1"))


class TestDedup:
    def test_exact_state_alerted_once(self, fresh_db):
        inc = _inc("dedup-user", "2026-01-01 10:00:00")
        assert alerter._already_alerted(inc) is False
        alerter._mark_alerted(inc)
        assert alerter._already_alerted(inc) is True

    def test_new_event_after_cooldown_not_blocked(self, fresh_db):
        # Alerted long ago (old sent_at): cooldown expired, and the new
        # incident state differs -> not blocked. The old sent_at is
        # inserted directly: calling _mark_alerted with cooldown=0 hits
        # a same-second boundary artifact (sent_at is stored with
        # second precision, so 'sent_at >= cutoff' holds within the
        # same second).
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT INTO alert_log (username,alert_key,severity,sent_at) VALUES (?,?,?,?)",
                ("dedup-user2",
                 alerter._alert_key(_inc("dedup-user2", "2026-01-01 10:00:00")),
                 "medium",
                 "2020-01-01 00:00:00"))
        assert alerter._already_alerted(_inc("dedup-user2", "2026-01-01 11:00:00")) is False

    def test_active_incident_suppressed_by_cooldown(self, fresh_db, monkeypatch):
        monkeypatch.setattr(alerter.settings, "alert_cooldown_min", 120)
        alerter._mark_alerted(_inc("dedup-user3", "2026-01-01 10:00:00"))
        # same user, new last_seen within cooldown -> suppressed
        assert alerter._already_alerted(_inc("dedup-user3", "2026-01-01 10:20:00")) is True


class TestFormat:
    def test_local_time_and_label(self, monkeypatch):
        class S:
            tg_proxy = ""
            alert_cooldown_min = 120
            timezone = "Europe/Moscow"
        monkeypatch.setattr(alerter, "settings", S)
        out = alerter._fmt_local("2026-01-01 10:00:00")
        assert out == "2026-01-01 13:00:00 MSK"

    def test_format_contains_local_time(self, monkeypatch):
        class S:
            tg_proxy = ""
            alert_cooldown_min = 120
            timezone = "Europe/Moscow"
        monkeypatch.setattr(alerter, "settings", S)
        text = alerter._format_incident(_inc("u1", "2026-01-01 10:00:00"))
        assert "2026-01-01 13:00:00 MSK" in text
        assert "UTC" not in text