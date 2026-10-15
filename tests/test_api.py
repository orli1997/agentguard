import importlib

from fastapi.testclient import TestClient

from agentguard.scenarios import by_id


def test_api_evaluate_and_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_AUDIT_DB", str(tmp_path / "api.db"))
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
