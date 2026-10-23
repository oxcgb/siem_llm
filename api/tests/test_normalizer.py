"""Normalizer unit tests: pure functions, no LLM, no network.

These cover the classes of bugs that historically reached production
(ISO timestamps with 'T', epoch handling, ADAP parsing).
"""
from normalizer import (
    convert_timestamp, classify_vpn_event, normalize_vpn_log,
    normalize_adap_log, deduplicate_and_aggregate, estimate_tokens,
)


class TestConvertTimestamp:
    def test_epoch_seconds(self):
        # 1730000000 = 2024-10-27 03:33:20 UTC
        assert convert_timestamp(1730000000) == "2024-10-27 03:33:20"

    def test_epoch_milliseconds(self):
        assert convert_timestamp(1730000000000) == "2024-10-27 03:33:20"

    def test_epoch_as_string(self):
        assert convert_timestamp("1730000000") == "2024-10-27 03:33:20"

    def test_iso_with_t(self):
        # the P1 bug: 'T' used to leak through and break correlation
        assert convert_timestamp("2026-01-02T03:04:05") == "2026-01-02 03:04:05"

    def test_iso_with_z(self):
        assert convert_timestamp("2026-01-02T03:04:05Z") == "2026-01-02 03:04:05"

    def test_iso_with_offset(self):
        # +03:00 offset must be converted to UTC, not truncated
        assert convert_timestamp("2026-01-02T06:04:05+03:00") == "2026-01-02 03:04:05"

    def test_space_format_passthrough(self):
        assert convert_timestamp("2026-01-02 03:04:05") == "2026-01-02 03:04:05"

    def test_empty(self):
        assert convert_timestamp("") == "N/A"
        assert convert_timestamp(None) == "N/A"

    def test_garbage_truncated(self):
        assert convert_timestamp("not-a-date-at-all") == "not-a-date-at-all"[:19]


class TestClassifyVpn:
    def test_asa_success(self):
        raw = {"MESSAGE": "%ASA-4-722051: Group policy ... User <ivanov> ..."}
        assert classify_vpn_event(raw) == "VPN_LOGIN_SUCCESS"

    def test_asa_rejected(self):
        raw = {"MESSAGE": "%ASA-6-113005: AAA user authentication Rejected"}
        assert classify_vpn_event(raw) == "VPN_LOGIN_FAILED"

    def test_unknown(self):
        assert classify_vpn_event({"MESSAGE": "random"}) == "UNKNOWN"


class TestNormalizeVpn:
    def test_full_success_event(self):
        raw = {
            "MESSAGE": "%ASA-4-722051: Group policy ENG ... User <petrov> "
                       "IP <203.0.113.5> IPv4 Address <10.8.0.42> assigned to session",
            "TIME": 1730000000,
        }
        ev = normalize_vpn_log(raw)
        assert ev["action"] == "login_success"
        assert ev["username"] == "petrov"
        assert ev["src_ip"] == "203.0.113.5"
        assert ev["private_ip"] == "10.8.0.42"
        assert ev["timestamp"] == "2024-10-27 03:33:20"

    def test_username_from_message_when_missing(self):
        raw = {"MESSAGE": "%ASA-6-113005: User <sidorov> IP <198.51.100.1>"}
        ev = normalize_vpn_log(raw)
        assert ev["username"] == "sidorov"

    def test_failed_login_ip(self):
        raw = {"MESSAGE": "AAA user authentication Rejected: user IP = 192.0.2.7"}
        ev = normalize_vpn_log(raw)
        assert ev["action"] == "login_failed"
        assert ev["src_ip"] == "192.0.2.7"


class TestNormalizeAdap:
    def test_4624_success(self):
        raw = {
            "MESSAGE": "[USER_NAME=smirnov][CLIENT_IP_ADDRESS=192.168.1.50]"
                       "[CLIENT_HOST_NAME=PC-01][EVENT_NUMBER=4624]"
                       "[TIME_GENERATED=2026-03-04T10:11:12]",
        }
        ev = normalize_adap_log(raw)
        assert ev["username"] == "smirnov"
        assert ev["src_ip"] == "192.168.1.50"
        assert ev["hostname"] == "PC-01"
        assert ev["action"] == "logon_success"
        assert ev["timestamp"] == "2026-03-04 10:11:12"

    def test_4625_failure(self):
        raw = {"MESSAGE": "[EVENT_NUMBER=4625][EVENT_TYPE_TEXT=Failure]"}
        ev = normalize_adap_log(raw)
        assert ev["action"] == "logon_failed"

    def test_4768_kerberos(self):
        raw = {"MESSAGE": "[EVENT_NUMBER=4768]"}
        ev = normalize_adap_log(raw)
        assert ev["action"] == "kerberos_tgt"


class TestDedup:
    def test_aggregates_similar(self):
        base = {"username": "a", "src_ip": "1.2.3.4", "event_type": "VPN_LOGIN_SUCCESS",
                "source_type": "VPN", "timestamp": "2026-01-01 10:00:00",
                "raw_message": "x"}
        events = [dict(base, timestamp="2026-01-01 10:00:00"),
                  dict(base, timestamp="2026-01-01 10:05:00"),
                  dict(base, timestamp="2026-01-01 10:10:00")]
        out = deduplicate_and_aggregate(events)
        assert len(out) == 1
        assert out[0]["event_count"] == 3
        assert "+2 similar" in out[0]["raw_message"]


class TestEstimateTokens:
    def test_conservative_ratio(self):
        # regression guard: len//4 underestimated 5x on real data
        text = '{"user":"a","ips":"1.2.3.4 (10:00)","facts":[1,2,3]}' * 10
        assert estimate_tokens(text) >= len(text) * 0.4

from normalizer import normalize_network_log


class TestNetworkEvents:
    # Real production samples (SIEM strips %ASA-4-733100: headers)

    def test_drop_rate_ip_subject(self):
        raw = {"MESSAGE": "[   10.77.20.0] drop rate-1 exceeded. Current burst rate "
                          "is 31 per second, max configured rate is 40; Current average "
                          "rate is 83 per second, max configured rate is 20; Cumulative "
                          "total count is 50210"}
        ev = normalize_network_log(raw)
        assert ev["action"] == "drop_rate_exceeded"
        assert ev["subject"] == "10.77.20.0"
        assert ev["subject_kind"] == "ip"
        assert ev["burst_rate"] == 31 and ev["burst_max"] == 40
        assert ev["avg_rate"] == 83 and ev["avg_max"] == 20
        assert ev["avg_ratio"] == 4.2  # 83/20
        assert ev["cumulative"] == 50210

    def test_drop_rate_proto_subject(self):
        raw = {"MESSAGE": "[  HTTP   80] drop rate-1 exceeded. Current burst rate "
                          "is 17 per second, max configured rate is 10; Current average "
                          "rate is 55 per second, max configured rate is 5; Cumulative "
                          "total count is 33072"}
        ev = normalize_network_log(raw)
        assert ev["action"] == "drop_rate_exceeded"
        assert ev["subject_kind"] == "proto"
        assert ev["protocol"] == "HTTP" and ev["dst_port"] == "80"
        assert ev["avg_ratio"] == 11.0  # 55/5 - the 11x offender

    def test_denied_ip_form(self):
        raw = {"MESSAGE": "denied IP: 10.1.2.10 (src) => 10.3.4.5 (dst)"}
        ev = normalize_network_log(raw)
        assert ev["action"] == "denied"
        assert ev["src_ip"] == "10.1.2.10" and ev["dst_ip"] == "10.3.4.5"

    def test_acl_denied_form(self):
        raw = {"MESSAGE": "access-list OUTSIDE-IN denied tcp 203.0.113.5(44444) -> 10.0.0.1(3389) hit-cnt 1 first hit"}
        ev = normalize_network_log(raw)
        assert ev["action"] == "acl_denied"
        assert ev["acl"] == "OUTSIDE-IN"
        assert ev["protocol"] == "TCP"
        assert ev["src_ip"] == "203.0.113.5" and ev["dst_port"] == "3389"

    def test_unknown_network_stays_other(self):
        ev = normalize_network_log({"MESSAGE": "some random cisco text"})
        assert ev["action"] == "network_other"
        assert ev["subject"] == "N/A"