"""Scoring / severity / coverage heuristics tests (pure functions) +
UEBA v1.6.0 tests: baseline-driven suppression of rule points (pure
_ueba_adjust tests) and end-to-end build_incidents runs on a seeded
temp database.

v1.6.2 additions: MITRE tags, the instant VPN->AD supporting signal,
watchlists (elevated / benign) and analyst triage (tp / fp per user-day).
"""
import datetime

import pytest

import incidents

UTC = datetime.timezone.utc
FMT = "%Y-%m-%d %H:%M:%S"


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


# --- UEBA v1.6.0 helpers ---------------------------------------------------

def _mk_baseline(active_days=6, hours=None, fail_median=0.0, countries=(),
                 fast_pairs=None, ad_uncov=0):
    return {
        "active_days": active_days,
        "hours": hours or {},
        "fail_median": fail_median,
        "countries": set(countries),
        "fast_pairs": fast_pairs or {},
        "ad_uncov_count": ad_uncov,
    }


def _mk_org(hours=None, fail_median=None, users=5):
    return {"users": users, "hours": hours or {}, "fail_median": fail_median}


def _adjust(rule_score=20, off_hours=False, off_utc=(), multi_geo=False,
            geo_gap=None, gap_pair=None, failed=0, failed_1h=0, ad_uncov=False,
            countries=(), baseline=None, org=None, instant=False, watchlists=()):
    return incidents._ueba_adjust(
        rule_score, off_hours, list(off_utc), multi_geo, geo_gap, gap_pair,
        failed, failed_1h, ad_uncov, set(countries), baseline, org,
        instant=instant, watchlists=set(watchlists))


class TestUebaAdjust:
    """_ueba_adjust: rule points suppressed by personal/peer history.
    Absolutes are never suppressed."""

    def test_disabled_returns_rule_score_unchanged(self, monkeypatch):
        monkeypatch.setitem(incidents._UEBA, "enabled", False)
        score, info = _adjust(rule_score=60, off_hours=True, off_utc=[2],
                              multi_geo=True, geo_gap=40, failed=8, failed_1h=3,
                              ad_uncov=True, countries=("RU", "KZ"),
                              baseline=_mk_baseline(fast_pairs={"KZ|RU": 9},
                                                    countries=("RU", "KZ")))
        assert score == 60
        assert info is None  # v1.5.0 payload shape when disabled

    def test_zero_rule_score_returns_no_info(self):
        score, info = _adjust(rule_score=0)
        assert (score, info) == (0, None)

    def test_off_hours_suppressed_personal(self):
        base = _mk_baseline(active_days=6, hours={21: 2, 22: 5, 23: 4})
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                              baseline=base)
        assert score == 0
        assert "off_hours" in info["suppressed"]
        assert info["personal"] is True

    def test_off_hours_kept_when_atypical(self):
        base = _mk_baseline(active_days=6, hours={9: 4, 10: 6, 18: 3})
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[23],
                              baseline=base)
        assert score == 20
        assert "off_hours" not in info["suppressed"]

    def test_off_hours_kept_when_only_some_events_typical(self):
        # one routine evening login + one genuinely weird one: keep
        base = _mk_baseline(active_days=6, hours={22: 5})
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22, 15],
                              baseline=base)
        assert score == 20

    def test_off_hours_tolerance_window(self):
        # 22 is not in the histogram, but 21 and 23 are (>= 3 total)
        base = _mk_baseline(active_days=6, hours={21: 1, 23: 3})
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                             baseline=base)
        assert score == 0

    def test_off_hours_midnight_wrap(self):
        # hour 0 flagged: tolerance reaches 23 of the previous day
        base = _mk_baseline(active_days=6, hours={23: 2, 0: 2, 1: 1})
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[0],
                             baseline=base)
        assert score == 0

    def test_off_hours_cold_user_peer_evidence(self):
        org = _mk_org(hours={21: ["u1", "u2", "u3", "u4"]}, fail_median=0)
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[21],
                              baseline=_mk_baseline(active_days=1), org=org)
        assert score == 0
        assert info["personal"] is False

    def test_off_hours_cold_user_no_peer_evidence(self):
        org = _mk_org(hours={21: ["u1"]}, fail_median=0)
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[21],
                              baseline=_mk_baseline(active_days=1), org=org)
        assert score == 20

    def test_off_hours_cold_user_adjacent_peer_hours(self):
        # peers at 20 and 22 count for a 21:00 login (tolerance)
        org = _mk_org(hours={20: ["u1", "u2"], 22: ["u3"]}, fail_median=0)
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[21],
                              baseline=_mk_baseline(active_days=1), org=org)
        assert score == 0

    def test_failed_within_personal_norm(self, monkeypatch):
        _mk_settings(monkeypatch)
        base = _mk_baseline(active_days=6, fail_median=8.0)
        score, info = _adjust(rule_score=15, failed=6, baseline=base)
        assert score == 0
        assert "failed_logins" in info["suppressed"]

    def test_failed_above_personal_norm_kept(self, monkeypatch):
        _mk_settings(monkeypatch)
        base = _mk_baseline(active_days=6, fail_median=1.0)
        score, info = _adjust(rule_score=15, failed=25, baseline=base)
        assert score == 15

    def test_failed_clean_user_not_suppressed(self, monkeypatch):
        # median 0 -> bound is 0*2+3=3: five failures (>= threshold)
        # stay fully scored - the classic brute signal
        _mk_settings(monkeypatch)
        base = _mk_baseline(active_days=6, fail_median=0.0)
        score, info = _adjust(rule_score=15, failed=5, baseline=base)
        assert score == 15

    def test_failed_cold_user_org_norm(self, monkeypatch):
        _mk_settings(monkeypatch)
        org = _mk_org(fail_median=7.0)
        score, info = _adjust(rule_score=15, failed=6,
                             baseline=_mk_baseline(active_days=1), org=org)
        assert score == 0

    def test_failed_cold_user_org_strict(self, monkeypatch):
        _mk_settings(monkeypatch)
        org = _mk_org(fail_median=0.0)
        score, info = _adjust(rule_score=15, failed=5,
                             baseline=_mk_baseline(active_days=1), org=org)
        assert score == 15

    def test_multigeo_all_countries_known(self):
        base = _mk_baseline(active_days=6, countries=("Russia", "Kazakhstan"))
        score, info = _adjust(rule_score=35, multi_geo=True, geo_gap=None,
                              countries=("Russia", "Kazakhstan"), baseline=base)
        assert score == 0
        assert "multi_geo" in info["suppressed"]

    def test_multigeo_new_country_kept(self):
        base = _mk_baseline(active_days=6, countries=("Russia",))
        score, info = _adjust(rule_score=35, multi_geo=True, geo_gap=None,
                              countries=("Russia", "Brazil"), baseline=base)
        assert score == 35

    def test_multigeo_not_suppressed_for_cold_user(self):
        base = _mk_baseline(active_days=1, countries=("Russia", "Kazakhstan"))
        score, info = _adjust(rule_score=35, multi_geo=True, geo_gap=None,
                              countries=("Russia", "Kazakhstan"), baseline=base)
        assert score == 35

    def test_multigeo_kept_when_impossible_travel(self):
        # gap <= 120 min: multi_geo suppression is skipped, the
        # fast-pair logic below decides the fate of both signals
        base = _mk_baseline(active_days=6, countries=("Russia", "Kazakhstan"))
        score, info = _adjust(rule_score=60, multi_geo=True, geo_gap=90,
                              gap_pair=("Russia", "Kazakhstan"),
                              countries=("Russia", "Kazakhstan"), baseline=base)
        assert score == 60

    def test_impossible_travel_routine_pair_suppressed(self):
        base = _mk_baseline(active_days=6, countries=("Russia", "Kazakhstan"),
                            fast_pairs={"Kazakhstan|Russia": 5})
        score, info = _adjust(rule_score=60, multi_geo=True, geo_gap=40,
                              gap_pair=("Russia", "Kazakhstan"),
                              countries=("Russia", "Kazakhstan"), baseline=base)
        assert score == 0
        assert "impossible_travel" in info["suppressed"]

    def test_impossible_travel_unknown_pair_kept(self):
        base = _mk_baseline(active_days=6, countries=("Russia", "Kazakhstan"),
                            fast_pairs={"Russia|US": 5})
        score, info = _adjust(rule_score=60, multi_geo=True, geo_gap=30,
                              gap_pair=("Russia", "Brazil"),
                              countries=("Russia", "Brazil"), baseline=base)
        assert score == 60

    def test_impossible_travel_pair_below_threshold_kept(self, monkeypatch):
        monkeypatch.setitem(incidents._UEBA, "pair_min", 3)
        base = _mk_baseline(active_days=6, countries=("Russia", "Kazakhstan"),
                            fast_pairs={"Kazakhstan|Russia": 2})
        score, info = _adjust(rule_score=60, multi_geo=True, geo_gap=50,
                              gap_pair=("Russia", "Kazakhstan"),
                              countries=("Russia", "Kazakhstan"), baseline=base)
        assert score == 60

    def test_ad_uncov_routine_suppressed(self):
        base = _mk_baseline(active_days=6, ad_uncov=9)
        score, info = _adjust(rule_score=10, ad_uncov=True, baseline=base)
        assert score == 0
        assert "ad_without_vpn" in info["suppressed"]

    def test_ad_uncov_not_routine_kept(self):
        base = _mk_baseline(active_days=6, ad_uncov=2)
        score, info = _adjust(rule_score=10, ad_uncov=True, baseline=base)
        assert score == 10

    def test_ad_uncov_not_suppressed_for_cold_user(self):
        base = _mk_baseline(active_days=1, ad_uncov=50)
        score, info = _adjust(rule_score=10, ad_uncov=True, baseline=base)
        assert score == 10

    def test_absolute_brute_success_floor(self, monkeypatch):
        _mk_settings(monkeypatch)
        base = _mk_baseline(active_days=6, hours={22: 5}, fail_median=8.0,
                           countries=("Russia", "Kazakhstan"),
                           fast_pairs={"Kazakhstan|Russia": 5})
        # 16 failures in the last hour: hours/fails/pairs would
        # suppress everything, but the absolute floor wins
        score, info = _adjust(rule_score=35, off_hours=True, off_utc=[22],
                              failed=16, failed_1h=16, multi_geo=True,
                              geo_gap=40, gap_pair=("Russia", "Kazakhstan"),
                              countries=("Russia", "Kazakhstan"), baseline=base)
        assert score == incidents._UEBA["abs_floor"] == 80
        assert info["absolute"] == "brute_force_success"

    def test_absolute_brute_below_threshold_no_floor(self, monkeypatch):
        _mk_settings(monkeypatch)
        base = _mk_baseline(active_days=6, hours={22: 5})
        # 14 in the last hour: below the absolute bar, so the routine
        # suppression applies as usual
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                              failed=14, failed_1h=14, baseline=base)
        assert score == 0
        assert "absolute" not in info

    def test_fail_open_without_baseline_and_org(self, monkeypatch):
        _mk_settings(monkeypatch)
        score, info = _adjust(rule_score=45, off_hours=True, off_utc=[2],
                              failed=8, ad_uncov=True, baseline=None, org=None)
        assert score == 45
        assert info["suppressed"] == []

    def test_combined_partial_suppression(self, monkeypatch):
        _mk_settings(monkeypatch)
        # off_hours routine (suppressed), ad_uncov not (kept): 30 -> 10
        base = _mk_baseline(active_days=6, hours={22: 5}, ad_uncov=1)
        score, info = _adjust(rule_score=30, off_hours=True, off_utc=[22],
                             ad_uncov=True, baseline=base)
        assert score == 10


# --- DB helpers -------------------------------------------------------------

def _s(dt):
    return dt.strftime(FMT)


def _past(hour, minute=0):
    """Latest occurrence of hour:minute UTC that is safely in the past
    (always inside the 24h incident window, whatever the wall clock)."""
    now = datetime.datetime.now(UTC)
    t = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if t >= now:
        t -= datetime.timedelta(days=1)
    return t


def _ago(**kw):
    return _s(datetime.datetime.now(UTC) - datetime.timedelta(**kw))


def _hist(base, days):
    """Same clock time on each of the previous `days` days."""
    return [_s(base - datetime.timedelta(days=d)) for d in range(1, days + 1)]


def _seed(db, user, vpn=(), ad=(), failed=(), ad_ip="10.0.0.50",
          vpn_ip="192.0.2.10"):
    """Seed events. TEST-NET VPN addresses classify as reserved, so geo
    resolves them offline to "Internal" and multi_geo never fires in
    DB tests; 10.0.0.50 is office-internal (AD covered, no VPN needed)."""
    with db.db() as conn:
        for ts in vpn:
            conn.execute(
                "INSERT INTO vpn_events (timestamp,username,src_ip,private_ip,action) "
                "VALUES (?,?,?,?, 'login_success')", (ts, user, vpn_ip, "10.8.0.5"))
        for ts in ad:
            conn.execute(
                "INSERT INTO ad_events (timestamp,username,src_ip,action,hostname) "
                "VALUES (?,?,?, 'logon_success', 'PC-1')", (ts, user, ad_ip))
        for ts in failed:
            conn.execute(
                "INSERT INTO vpn_events (timestamp,username,src_ip,action) "
                "VALUES (?,?,'192.0.2.99','login_failed')", (ts, user))


def _worker(db, user="night", hour=22, minute=30, days=5):
    """A user with `days` days of history at hour:minute UTC + today."""
    base = _past(hour, minute)
    base_ad = base + datetime.timedelta(minutes=5)
    _seed(db, user,
          vpn=[_s(base)] + _hist(base, days),
          ad=[_s(base_ad)] + _hist(base_ad, days))


class TestUebaBuild:
    """End-to-end: build_incidents on a seeded temp database. The wall
    clock is irrelevant: 22:30 UTC is off-hours both for the UTC
    timezone (>= 20) and for Europe/Moscow (01:30 < 08)."""

    def test_night_worker_suppressed_and_rollback(self, fresh_db, monkeypatch):
        _worker(fresh_db)

        # automatic mode: the night worker is gone (20 -> 0 < 20)
        out = incidents.build_incidents()
        assert "night" not in {i["username"] for i in out}

        # manual mode still returns the user, with the explanation
        (man,) = incidents.build_incidents({"night"})
        assert man["rule_score"] == 20
        assert man["risk_score"] == 0
        assert "off_hours" in man["ueba"]["suppressed"]
        assert man["ueba"]["personal"] is True

        # rollback: UEBA_ENABLED=false restores exact v1.5.0 behaviour
        monkeypatch.setitem(incidents._UEBA, "enabled", False)
        (old,) = incidents.build_incidents({"night"})
        assert old["risk_score"] == 20
        assert "rule_score" not in old
        assert "ueba" not in old
        # v1.6.2 keys must not leak into the v1.5.0 payload either
        assert "mitre" not in old
        assert "watchlists" not in old
        assert "triage" not in old

    def test_soft_kill_switch_via_db(self, fresh_db):
        _worker(fresh_db)
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key,value) "
                "VALUES ('ueba_enabled','false')")
        (inc,) = incidents.build_incidents({"night"})
        assert inc["risk_score"] == 20
        assert "ueba" not in inc

    def test_new_attacker_still_flagged(self, fresh_db):
        _worker(fresh_db)  # established user defines the peer profile

        # attacker appeared TODAY ONLY: off-hours + 8 failed logins,
        # no personal history, no peer evidence at 23:xx
        _seed(fresh_db, "attacker",
              vpn=[_s(_past(23, 10))], ad=[_s(_past(23, 15))],
              failed=[_ago(minutes=50 - 3 * i) for i in range(8)])

        out = incidents.build_incidents()
        names = {i["username"] for i in out}
        assert "attacker" in names
        assert "night" not in names
        (inc,) = [i for i in out if i["username"] == "attacker"]
        assert inc["risk_score"] == 35  # off_hours 20 + failed 15
        assert inc["ueba"]["personal"] is False

    def test_brute_force_success_absolute(self, fresh_db):
        # established day worker whose account is brute-forced within
        # the last hour: absolute signal, floor 80, severity high
        _worker(fresh_db, user="victim", hour=10, minute=0)
        _seed(fresh_db, "victim",
              vpn=[_ago(minutes=20)], ad=[_ago(minutes=15)],
              failed=[_ago(minutes=55 - 3 * i) for i in range(16)])

        out = incidents.build_incidents()
        (inc,) = [i for i in out if i["username"] == "victim"]
        assert inc["risk_score"] == 80
        assert inc["severity"] == "high"
        assert inc["ueba"]["absolute"] == "brute_force_success"

    def test_baseline_rebuild_profiles(self, fresh_db):
        _worker(fresh_db)
        assert incidents.rebuild_baselines(force=True) is True
        profiles, org = incidents._ensure_baselines()
        b = profiles["night"]
        assert b["active_days"] == 6
        assert b["hours"].get(22, 0) >= 10          # 6 days x (VPN + AD)
        assert b["fail_median"] == 0.0
        assert b["countries"] == set()             # TEST-NET -> Internal
        assert b["fast_pairs"] == {}
        assert b["ad_uncov_count"] == 0
        assert org["users"] == 1
        assert org["fail_median"] == 0.0
        assert org["hours"].get(22) == ["night"]   # established users only

    def test_baseline_fast_pairs_and_countries(self, fresh_db):
        # geo_cache seeding keeps geo fully offline (30-day TTL)
        now_s = datetime.datetime.now(UTC).strftime(FMT)
        with fresh_db.db() as conn:
            for ip, geo in (("1.2.3.4", "Russia, Moscow"),
                            ("5.6.7.8", "Kazakhstan, Almaty")):
                conn.execute(
                    "INSERT INTO geo_cache (ip,geo,timezone,fetched_at) "
                    "VALUES (?,?,?,?)", (ip, geo, "", now_s))

        # 5 days: RU login at 10:00, KZ login 30 minutes later -> the
        # same fast pair every day (routine geo flip, e.g. mobile ISP)
        base = _past(10, 0)
        vpn_ts = []
        for d in range(5):
            day = base - datetime.timedelta(days=d)
            vpn_ts += [_s(day), _s(day + datetime.timedelta(minutes=30))]
        ad_ts = [_s(base - datetime.timedelta(days=d, minutes=-35)) for d in range(5)]
        with fresh_db.db() as conn:
            for i, ts in enumerate(vpn_ts):
                ip = "1.2.3.4" if i % 2 == 0 else "5.6.7.8"
                conn.execute(
                    "INSERT INTO vpn_events (timestamp,username,src_ip,private_ip,action) "
                    "VALUES (?,?,?,?, 'login_success')", (ts, "traveler", ip, "10.8.0.7"))
            for ts in ad_ts:
                conn.execute(
                    "INSERT INTO ad_events (timestamp,username,src_ip,action,hostname) "
                    "VALUES (?,?,'10.0.0.50', 'logon_success', 'PC-1')", (ts, "traveler"))

        assert incidents.rebuild_baselines(force=True) is True
        profiles, _org = incidents._ensure_baselines()
        b = profiles["traveler"]
        assert b["active_days"] == 5
        assert b["countries"] == {"Russia", "Kazakhstan"}
        assert b["fast_pairs"] == {"Kazakhstan|Russia": 5}

    def test_staleness_heartbeat(self, fresh_db):
        with fresh_db.db() as conn:
            assert incidents._baselines_stale(conn) is True  # never built
        assert incidents.rebuild_baselines(force=True) is True
        with fresh_db.db() as conn:
            assert incidents._baselines_stale(conn) is False  # fresh heartbeat
        # not stale -> a rebuild without force=True is a no-op
        assert incidents.rebuild_baselines(force=False) is False


class TestUebaConfig:
    """v1.6.1: layered runtime configuration (defaults <- env <- settings)."""

    def test_validate_partial_ok(self):
        clean, errors = incidents.validate_ueba_overrides(
            {"min_days": 5, "fail_mult": 2.5})
        assert errors == []
        assert clean == {"min_days": 5, "fail_mult": 2.5}

    def test_validate_coerces_strings_and_bool(self):
        clean, errors = incidents.validate_ueba_overrides(
            {"enabled": "false", "pair_min": "4"})
        assert errors == []
        assert clean == {"enabled": False, "pair_min": 4}

    def test_validate_rejects_out_of_range(self):
        clean, errors = incidents.validate_ueba_overrides(
            {"min_days": 0, "abs_floor": 101, "fail_mult": 99})
        assert clean == {}
        assert len(errors) == 3

    def test_validate_rejects_unknown_and_fractional(self):
        _clean, errors = incidents.validate_ueba_overrides(
            {"nope": 1, "pair_min": 2.5})
        assert "unknown setting: nope" in errors
        assert any("integer" in e for e in errors)

    def test_validate_non_dict(self):
        _clean, errors = incidents.validate_ueba_overrides("junk")
        assert errors == ["body must be a JSON object"]

    def test_effective_config_db_overrides_env(self, fresh_db):
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('ueba_min_days', '7')")
        cfg = incidents.effective_ueba_config()
        assert cfg["min_days"] == 7
        assert cfg["pair_min"] == incidents._env_defaults()["pair_min"]

    def test_effective_config_broken_values_ignored(self, fresh_db):
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('ueba_pair_min', 'junk')")
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('ueba_abs_floor', '999')")
        cfg = incidents.effective_ueba_config()
        assert cfg["pair_min"] == 3
        assert cfg["abs_floor"] == 80

    def test_effective_config_runtime_switch(self, fresh_db):
        assert incidents.effective_ueba_config()["enabled"] is True
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('ueba_enabled', 'false')")
        assert incidents.effective_ueba_config()["enabled"] is False

    def test_env_hard_switch_beats_db_true(self, fresh_db, monkeypatch):
        monkeypatch.setitem(incidents._UEBA, "enabled", False)
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('ueba_enabled', 'true')")
        cfg = incidents.effective_ueba_config()
        assert cfg["enabled"] is False
        assert cfg["env_forced_off"] is True

    def test_refresh_folds_db_into_live_dict(self, fresh_db, monkeypatch):
        monkeypatch.setitem(incidents._UEBA, "hour_min_occ", 99)  # any drift
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('ueba_hour_min_occ', '5')")
        incidents.refresh_ueba_config()
        assert incidents._UEBA["hour_min_occ"] == 5
        assert incidents._UEBA["min_days"] == incidents._env_defaults()["min_days"]

    def test_refresh_fail_open_keeps_previous(self, monkeypatch):
        monkeypatch.setitem(incidents._UEBA, "pair_min", 42)
        # broken DB layer -> exception swallowed, values untouched
        def _boom():
            raise RuntimeError("db down")
        monkeypatch.setattr(incidents, "_env_defaults", _boom)
        incidents.refresh_ueba_config()
        assert incidents._UEBA["pair_min"] == 42

    def test_status_shape(self, fresh_db):
        st = incidents.ueba_status()
        assert set(st) == {"enabled", "env_forced_off", "config",
                           "overrides", "baselines"}
        assert st["enabled"] is True
        assert st["env_forced_off"] is False
        assert st["baselines"]["users"] == 0
        assert st["config"]["min_days"] == 3

    def test_status_reports_overrides_and_baselines(self, fresh_db):
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('ueba_min_days', '4')")
        st = incidents.ueba_status()
        assert st["overrides"] == {"min_days": 4}
        assert incidents.rebuild_baselines(force=True) is True
        st2 = incidents.ueba_status()
        assert st2["baselines"]["updated_at"] != ""


# --- v1.6.2: MITRE tags -----------------------------------------------------

class TestMitre:
    """MITRE ATT&CK labels are attached only for the rules that actually
    contribute to the final score (suppressed = routine -> no tags)."""

    def test_tags_deduplicated(self):
        assert incidents._mitre_tags(
            ["off_hours", "multi_geo", "impossible_travel", "instant_switch"]) \
            == ["T1078 Valid Accounts"]
        assert incidents._mitre_tags(
            ["failed_logins", "brute_force_success"]) == ["T1110 Brute Force"]
        assert incidents._mitre_tags(["ad_without_vpn"]) == ["T1021 Remote Services"]

    def test_unknown_signal_ignored(self):
        assert incidents._mitre_tags(["nope"]) == []

    def test_build_tags_attacker(self, fresh_db):
        _worker(fresh_db)  # established peer defines the profile
        _seed(fresh_db, "attacker",
              vpn=[_s(_past(23, 10))], ad=[_s(_past(23, 15))],
              failed=[_ago(minutes=50 - 3 * i) for i in range(8)])
        (inc,) = [i for i in incidents.build_incidents()
                  if i["username"] == "attacker"]
        assert set(inc["mitre"]) == {"T1078 Valid Accounts", "T1110 Brute Force"}

    def test_build_suppressed_rules_not_tagged(self, fresh_db):
        _worker(fresh_db)
        (man,) = incidents.build_incidents({"night"})
        # off_hours is personal routine -> suppressed -> deliberately untagged
        assert man["mitre"] == []

    def test_build_absolute_tagged(self, fresh_db):
        _worker(fresh_db, user="victim", hour=10, minute=0)
        _seed(fresh_db, "victim",
              vpn=[_ago(minutes=20)], ad=[_ago(minutes=15)],
              failed=[_ago(minutes=55 - 3 * i) for i in range(16)])
        (inc,) = [i for i in incidents.build_incidents()
                  if i["username"] == "victim"]
        assert "T1110 Brute Force" in inc["mitre"]


# --- v1.6.2: instant VPN->AD supporting signal ------------------------------

class TestInstant:
    """Scripted-access bonus (+10): fires only on top of another rule
    that survived suppression; never on its own; never for benign."""

    def test_signal_threshold(self, monkeypatch):
        monkeypatch.setitem(incidents._UEBA, "instant_min_diff", 2.0)
        assert incidents._instant_signal(None) is False
        assert incidents._instant_signal(0.0) is True
        assert incidents._instant_signal(2.0) is True
        assert incidents._instant_signal(2.1) is False

    def test_no_bonus_when_parent_suppressed(self, monkeypatch):
        _mk_settings(monkeypatch)
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                              instant=True,
                              baseline=_mk_baseline(hours={22: 10}))
        assert score == 0
        assert "bonus" not in info

    def test_bonus_when_parent_survives(self, monkeypatch):
        _mk_settings(monkeypatch)
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                              instant=True,
                              baseline=_mk_baseline(hours={10: 5}))
        assert score == 30
        assert info.get("bonus") == ["instant_switch"]

    def test_no_bonus_for_benign(self, monkeypatch):
        _mk_settings(monkeypatch)
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                              instant=True, watchlists=("benign",))
        assert score == 0
        assert "bonus" not in info
        assert "off_hours" in info["suppressed"]

    def test_elevated_keeps_bonus(self, monkeypatch):
        _mk_settings(monkeypatch)
        # routine night hours would suppress; elevated bypasses + bonus stays
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                              instant=True, watchlists=("elevated",),
                              baseline=_mk_baseline(hours={22: 10}))
        assert score == 30
        assert info["suppressed"] == []

    def test_build_instant_amplifies_off_hours(self, fresh_db):
        _worker(fresh_db)  # peer profile (1 user: too weak to suppress)
        # VPN login followed by AD activity one minute later at 23:2x
        _seed(fresh_db, "robot",
              vpn=[_s(_past(23, 20))], ad=[_s(_past(23, 21))])
        (inc,) = [i for i in incidents.build_incidents()
                  if i["username"] == "robot"]
        assert inc["rule_score"] == 20
        assert inc["risk_score"] == 30
        assert inc["ueba"]["bonus"] == ["instant_switch"]
        assert "T1078 Valid Accounts" in inc["mitre"]

    def test_build_normal_pause_not_instant(self, fresh_db):
        _worker(fresh_db)
        # 5-minute human pause between VPN and AD: no bonus
        _seed(fresh_db, "human",
              vpn=[_s(_past(23, 20))], ad=[_s(_past(23, 25))])
        (inc,) = [i for i in incidents.build_incidents()
                  if i["username"] == "human"]
        assert inc["rule_score"] == 20
        assert inc["risk_score"] == 20
        assert "bonus" not in inc["ueba"]


# --- v1.6.2: watchlists ------------------------------------------------------

class TestWatchlists:
    """elevated: suppression bypassed. benign: noise always suppressed,
    absolutes still floor. Unknown list names are ignored defensively."""

    def test_crud_roundtrip(self, fresh_db):
        assert incidents.list_watchlists() == []
        row_id = incidents.add_watchlist("alice", "elevated", "leaver", "admin")
        incidents.add_watchlist("svc_backup", "benign", "monitoring", "admin")
        rows = incidents.list_watchlists()
        assert {(r["username"], r["list_name"]) for r in rows} \
            == {("alice", "elevated"), ("svc_backup", "benign")}
        # upsert: same (user, list) updated in place, not duplicated
        incidents.add_watchlist("alice", "elevated", "updated note", "admin2")
        rows = incidents.list_watchlists()
        assert len(rows) == 2
        alice = [r for r in rows if r["username"] == "alice"][0]
        assert alice["note"] == "updated note"
        assert incidents.remove_watchlist(row_id) is True
        assert incidents.remove_watchlist(row_id) is False
        assert all(r["username"] != "alice" for r in incidents.list_watchlists())

    def test_load_ignores_unknown_lists(self, fresh_db):
        incidents.add_watchlist("x", "elevated")
        with fresh_db.db() as conn:
            conn.execute(
                "INSERT INTO watchlist (username,list_name) VALUES ('y','weird')")
        assert incidents._load_watchlists() == {"x": {"elevated"}}

    def test_elevated_bypasses_personal_suppression(self, monkeypatch):
        _mk_settings(monkeypatch)
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                              watchlists=("elevated",),
                              baseline=_mk_baseline(hours={22: 10}))
        assert score == 20
        assert info["suppressed"] == []
        assert info["watchlists"] == ["elevated"]

    def test_benign_suppresses_without_baseline(self, monkeypatch):
        _mk_settings(monkeypatch)
        score, info = _adjust(rule_score=60, off_hours=True, off_utc=[3],
                              multi_geo=True, geo_gap=30, failed=9,
                              ad_uncov=True, watchlists=("benign",))
        assert score == 0
        assert set(info["suppressed"]) == {"off_hours", "failed_logins",
                                           "multi_geo", "impossible_travel",
                                           "ad_without_vpn"}

    def test_benign_absolute_still_floors(self, monkeypatch):
        _mk_settings(monkeypatch)
        score, info = _adjust(rule_score=35, off_hours=True, off_utc=[3],
                              failed=20, failed_1h=20, watchlists=("benign",))
        assert score == 80
        assert info["absolute"] == "brute_force_success"

    def test_unknown_watchlist_has_no_effect(self, monkeypatch):
        _mk_settings(monkeypatch)
        score, info = _adjust(rule_score=20, off_hours=True, off_utc=[22],
                              watchlists=("weird",),
                              baseline=_mk_baseline(hours={22: 10}))
        assert score == 0  # ordinary personal suppression still applies
        assert info["watchlists"] == ["weird"]

    def test_build_elevated_user_resurfaces(self, fresh_db):
        _worker(fresh_db)  # routine night worker: normally suppressed to 0
        incidents.add_watchlist("night", "elevated", "VIP", "admin")
        (man,) = incidents.build_incidents({"night"})
        assert man["watchlists"] == ["elevated"]
        assert man["risk_score"] == 20
        assert man["mitre"] == ["T1078 Valid Accounts"]
        # and back in the automatic list as well
        assert "night" in {i["username"] for i in incidents.build_incidents()}

    def test_build_benign_service_account_silent(self, fresh_db):
        _worker(fresh_db)
        # brand-new service account logging in at 23:00 (cold, no baseline)
        _seed(fresh_db, "svc_probe", vpn=[_s(_past(23, 0))], ad=[_s(_past(23, 5))])
        incidents.add_watchlist("svc_probe", "benign", "monitoring", "admin")
        assert "svc_probe" not in {i["username"] for i in incidents.build_incidents()}
        (man,) = incidents.build_incidents({"svc_probe"})
        assert man["risk_score"] == 0
        assert man["watchlists"] == ["benign"]


# --- v1.6.2: analyst triage -------------------------------------------------

def _intruder(db, user="intruder"):
    """Cold attacker with off-hours + failures: 35 in the automatic list."""
    _seed(db, user, vpn=[_s(_past(23, 10))], ad=[_s(_past(23, 15))],
          failed=[_ago(minutes=50 - 3 * i) for i in range(8)])


class TestTriage:
    """Verdicts per (user, UTC-day): fp leaves the automatic list and
    stops alerting; tp stays visible with the verdict attached."""

    def test_save_upsert_and_delete(self, fresh_db):
        incidents.save_triage("alice", "2026-01-01", "fp", "phone typo",
                              "bob", ["off_hours"])
        incidents.save_triage("alice", "2026-01-01", "tp", "", "bob",
                              ["off_hours"])
        m = incidents._load_triage()
        assert m[("alice", "2026-01-01")]["status"] == "tp"
        assert incidents.delete_triage("alice", "2026-01-01") is True
        assert incidents.delete_triage("alice", "2026-01-01") is False
        assert incidents._load_triage() == {}

    def test_invalid_status_rejected(self, fresh_db):
        with pytest.raises(ValueError):
            incidents.save_triage("a", "2026-01-01", "junk")

    def test_fp_excluded_from_auto_list(self, fresh_db):
        _worker(fresh_db)
        _intruder(fresh_db)
        (inc,) = [i for i in incidents.build_incidents()
                  if i["username"] == "intruder"]
        assert inc["risk_score"] == 35
        d = inc["last_seen"][:10]
        incidents.save_triage("intruder", d, "fp", "authorized pentest",
                              "analyst", ["off_hours", "failed_logins"])

        out = incidents.build_incidents()
        assert "intruder" not in {i["username"] for i in out}

        # manual mode still returns the user, verdict attached
        (man,) = incidents.build_incidents({"intruder"})
        assert man["triage"]["status"] == "fp"
        assert man["triage"]["reason"] == "authorized pentest"
        assert man["triage"]["date"] == d

        # reopen: the incident returns to the automatic list
        assert incidents.delete_triage("intruder", d) is True
        assert "intruder" in {i["username"] for i in incidents.build_incidents()}

    def test_tp_kept_visible_with_verdict(self, fresh_db):
        _worker(fresh_db)
        _intruder(fresh_db)
        (inc,) = [i for i in incidents.build_incidents()
                  if i["username"] == "intruder"]
        incidents.save_triage("intruder", inc["last_seen"][:10], "tp",
                              "real attack", "analyst", ["off_hours"])
        out = incidents.build_incidents()
        (inc2,) = [i for i in out if i["username"] == "intruder"]
        assert inc2["triage"]["status"] == "tp"

    def test_fp_not_excluded_when_ueba_off(self, fresh_db, monkeypatch):
        # kill-switch must restore exact v1.5.0 behaviour: no fp filter
        _worker(fresh_db)
        _intruder(fresh_db)
        (inc,) = [i for i in incidents.build_incidents()
                  if i["username"] == "intruder"]
        incidents.save_triage("intruder", inc["last_seen"][:10], "fp", "", "a")
        monkeypatch.setitem(incidents._UEBA, "enabled", False)
        assert "intruder" in {i["username"] for i in incidents.build_incidents()}

    def test_stats_totals_precision_and_per_rule(self, fresh_db):
        incidents.save_triage("a", "2026-01-01", "tp", rules=["off_hours"])
        incidents.save_triage("b", "2026-01-01", "fp", rules=["off_hours"])
        incidents.save_triage("c", "2026-01-02", "fp", rules=["failed_logins"])
        st = incidents.triage_stats()
        assert st["total"] == {"tp": 1, "fp": 2}
        assert st["precision"] == 33.3
        assert st["per_rule"]["off_hours"] == {"tp": 1, "fp": 1}
        assert st["per_rule"]["failed_logins"] == {"tp": 0, "fp": 1}
        assert len(st["recent"]) == 3

    def test_stats_empty_db(self, fresh_db):
        st = incidents.triage_stats()
        assert st == {"total": {"tp": 0, "fp": 0}, "precision": None,
                      "per_rule": {}, "recent": []}
