"""Scoring / severity / coverage heuristics tests (pure functions)."""
import incidents


def _mk_settings(monkeypatch, **kw):
    class S:
        brute_force_threshold = kw.get("bft", 5)
        off_hours_start = kw.get("ohs", 20)
        off_hours_end = kw.get("ohe", 8)
        timezone = kw.get("tz", "UTC")
        incident_min_score = kw.get("ims", 20)
    monkeypatch.setattr(incidents, "settings", S)


class TestScore:
    def test_clean_user_zero(self, monkeypatch):
        _mk_settings(monkeypatch)
        assert incidents._calc_score(False, None, False, 0, False) == 0

    def test_multi_geo_alone(self, monkeypatch):
        _mk_settings(monkeypatch)
        # multi_geo without a measured gap
        assert incidents._calc_score(True, None, False, 0, False) == 35

    def test_impossible_travel(self, monkeypatch):
        _mk_settings(monkeypatch)
        assert incidents._calc_score(True, 30, False, 0, False) == 60  # 35+25

    def test_off_hours_brute(self, monkeypatch):
        _mk_settings(monkeypatch)
        # off_hours + failed >= threshold
        assert incidents._calc_score(False, None, True, 5, False) == 35  # 20+15

    def test_capped_at_100(self, monkeypatch):
        _mk_settings(monkeypatch)
        assert incidents._calc_score(True, 10, True, 99, True) == 100

    def test_failed_below_threshold_scores_zero(self, monkeypatch):
        _mk_settings(monkeypatch, bft=5)
        # 4 failures < threshold: no brute points
        assert incidents._calc_score(False, None, False, 4, False) == 0


class TestSeverity:
    def test_bands(self):
        assert incidents._calc_severity(100) == "high"
        assert incidents._calc_severity(70) == "high"
        assert incidents._calc_severity(69) == "medium"
        assert incidents._calc_severity(40) == "medium"
        assert incidents._calc_severity(39) == "low"
        assert incidents._calc_severity(20) == "low"
        assert incidents._calc_severity(19) == "info"


class TestAdCoverage:
    # NOTE on test IPs: documentation ranges (TEST-NET) like
    # 203.0.113.0/24 and 198.51.100.0/24 are classified as PRIVATE by
    # Python's ipaddress module - using them as "public" IPs made these
    # tests pass/fail for the wrong reason. 93.184.216.34 is genuinely
    # public.
    def test_internal_ad_ip_never_flagged(self):
        u_ad = [("2026-01-01 12:00:00", "10.0.0.50", "PC-01")]
        assert incidents._check_ad_coverage(u_ad, sessions=[]) is False

    def test_public_ad_ip_without_vpn_flagged(self):
        u_ad = [("2026-01-01 12:00:00", "93.184.216.34", "ext-host")]
        assert incidents._check_ad_coverage(u_ad, sessions=[]) is True

    def test_public_ad_ip_inside_vpn_window_covered(self):
        u_ad = [("2026-01-01 12:00:00", "93.184.216.34", "ext-host")]
        sessions = [("2026-01-01 11:50:00", None, "10.8.0.42")]  # open session
        assert incidents._check_ad_coverage(u_ad, sessions) is False

    def test_public_ad_ip_outside_vpn_window_flagged(self):
        u_ad = [("2026-01-01 23:00:00", "93.184.216.34", "ext-host")]
        sessions = [("2026-01-01 10:00:00", "2026-01-01 10:30:00", "10.8.0.42")]
        assert incidents._check_ad_coverage(u_ad, sessions) is True