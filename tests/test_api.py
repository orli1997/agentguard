import importlib

from fastapi.testclient import TestClient

from agentguard.scenarios import by_id


def test_api_evaluate_and_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_AUDIT_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AGENTGUARD_LEDGER_DB", str(tmp_path / "ledger.db"))
    import agentguard.api as api
    importlib.reload(api)
    client = TestClient(api.app)

    body = by_id("A07").request().model_dump(mode="json")
    r = client.post("/v1/evaluate", json=body)
    assert r.status_code == 200
    assert r.json()["decision"] == "BLOCK"

    assert client.post("/v1/evaluate", json=by_id("A01").request().model_dump(mode="json")).json()["decision"] == "APPROVE"
    assert client.get("/v1/audit/verify").json() == {"ok": True, "first_bad_seq": None}


def test_api_rejects_malformed_request():
    import agentguard.api as api
    client = TestClient(api.app)
    assert client.post("/v1/evaluate", json={"request_id": "x"}).status_code == 422


def test_api_signed_mandate_budget(tmp_path, monkeypatch):
    """Over HTTP: JSON-serialized mandate verifies, and the ledger enforces the 4-payment cap."""
    monkeypatch.setenv("AGENTGUARD_AUDIT_DB", str(tmp_path / "a.db"))
    monkeypatch.setenv("AGENTGUARD_LEDGER_DB", str(tmp_path / "l.db"))
    import agentguard.api as api
    from agentguard.scenarios_phase2 import NOW, by_id2
    importlib.reload(api)
    api.guard.clock = lambda: NOW
    client = TestClient(api.app)
    body = by_id2("M01").request().model_dump(mode="json")
    out = [client.post("/v1/evaluate", json={**body, "request_id": f"p{i}"}).json()["decision"] for i in range(5)]
    assert out == ["APPROVE"] * 4 + ["BLOCK"]
