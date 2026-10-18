from fastapi.testclient import TestClient
from app.main import app
from test_discovery import fixture


def test_account_list_metadata_never_exposes_credentials():
    target = fixture()
    client = TestClient(app)
    headers = {"X-API-Key": "test-token"}
    result = client.post(f"/api/targets/{target['id']}/accounts", headers=headers,
        json=dict(name="Admin test", role="admin", headers={"Authorization":"Bearer synthetic-private-token"}, synthetic_data_only=True))
    assert result.status_code == 200
    state = client.get("/api/state", headers=headers)
    account = next(a for a in state.json()["account"] if a["id"] == result.json()["id"])
    assert account["header_names"] == ["Authorization"]
    assert account["created_at"] > 0
    assert "synthetic-private-token" not in state.text
    assert "encrypted_headers" not in account
