"""Integration test: network events must land in network_events, not
vpn_events. Regression guard for the missing INSERT branch that
silently routed network events into vpn_events."""
import agent


NETWORK_ENTRY = {
    "MESSAGE": "[ 10.77.20.99] drop rate-1 exceeded. Current burst rate "
               "is 5 per second, max configured rate is 10; Current average "
               "rate is 12 per second, max configured rate is 4; Cumulative "
               "total count is 1000",
    "TIME": 1730000000,
}


class _FakeResp:
    status_code = 200
    text = ""

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": {"hits": [NETWORK_ENTRY]}}


class _FakeClient:
    def __init__(self, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, headers=None, json=None):
        return _FakeResp()


def test_network_event_routed_to_network_table(fresh_db, monkeypatch):
    with fresh_db.db() as conn:
        conn.execute(
            "INSERT INTO datasources (id,name,api_url,auth_header,payload_json) "
            "VALUES ('test-ds','fake','http://10.0.0.1/api','','{}')")

    monkeypatch.setattr(agent, "resolve_allowed_target",
                        lambda url: "http://127.0.0.1:9/api")
    monkeypatch.setattr(agent.httpx, "Client", _FakeClient)

    saved = agent.fetch_and_store_logs("test-rule", manual=True)
    assert saved >= 1

    with fresh_db.db() as conn:
        net = conn.execute("SELECT COUNT(*) c FROM network_events").fetchone()["c"]
        vpn_leak = conn.execute(
            "SELECT COUNT(*) c FROM vpn_events WHERE raw_event LIKE '%drop rate%'"
        ).fetchone()["c"]

    assert net == 1, "network event must be stored in network_events"
    assert vpn_leak == 0, "network event must NOT leak into vpn_events"