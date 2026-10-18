import json

from app.model_management import authenticated, provider_settings, router
from app.security import decrypt
from app.store import Record, Session
from fastapi import FastAPI
from fastapi.testclient import TestClient

app = FastAPI()
app.include_router(router)
app.dependency_overrides[authenticated] = lambda: None
client = TestClient(app)


def payload(**changes):
    return dict(
        name="DeepSeek",
        base_url="https://api.deepseek.com",
        model="test-model",
        api_key="private-test-key",
        **changes,
    )


def test_saved_key_survives_sessions_and_blank_edit():
    response = client.post("/api/model-configs", json=payload())
    assert response.status_code == 200
    ident = response.json()["id"]
    assert response.json()["has_api_key"]
    assert "private-test-key" not in response.text
    with Session() as s:
        stored = s.get(Record, ident).payload
        assert "private-test-key" not in stored
        assert decrypt(json.loads(stored)["encrypted_key"]) == "private-test-key"
    edited = payload()
    edited.update(name="renamed", api_key="")
    assert client.put(f"/api/model-configs/{ident}", json=edited).status_code == 200
    with Session() as s:
        assert (
            decrypt(json.loads(s.get(Record, ident).payload)["encrypted_key"])
            == "private-test-key"
        )
    listed = client.get("/api/model-configs").json()
    assert listed[0]["name"] == "renamed"
    assert listed[0]["has_api_key"]
    assert "encrypted_key" not in listed[0]
    assert client.delete(f"/api/model-configs/{ident}").status_code == 200
    assert client.get("/api/model-configs").json() == []


def test_policy_settings_persist_without_implicitly_trusting_connections(monkeypatch):
    monkeypatch.setenv("MODEL_CLOUD_BASE_URLS", "https://models.example/v1")
    assert provider_settings()["MODEL_CLOUD_BASE_URLS"] == "https://models.example/v1"
    assert client.post("/api/model-configs", json=payload()).status_code == 200
    assert "deepseek" not in provider_settings()["MODEL_CLOUD_BASE_URLS"]
    settings = {
        "MODEL_CLOUD_BASE_URLS": "https://api.deepseek.com/",
        "MODEL_LOCAL_BASE_URLS": "http://localhost:11434/v1",
        "MODEL_MAX_USD_PER_MILLION_TOKENS": 10,
    }
    assert client.put("/api/model-settings", json=settings).status_code == 200
    monkeypatch.setenv("MODEL_CLOUD_BASE_URLS", "https://changed.example")
    current = provider_settings()
    assert current["MODEL_CLOUD_BASE_URLS"] == "https://api.deepseek.com"
    assert current["MODEL_MAX_USD_PER_MILLION_TOKENS"] == 10
    assert client.get("/api/model-settings").json() == current


def test_invalid_settings_and_provider_url_rejected():
    assert (
        client.put(
            "/api/model-settings",
            json={"MODEL_CLOUD_BASE_URLS": "http://cloud.example"},
        ).status_code
        == 400
    )
    assert (
        client.put(
            "/api/model-settings", json={"MODEL_MAX_USD_PER_MILLION_TOKENS": -1}
        ).status_code
        == 422
    )
    body = payload()
    body["base_url"] = "https://user:password@example.com"
    assert client.post("/api/model-configs", json=body).status_code == 400
