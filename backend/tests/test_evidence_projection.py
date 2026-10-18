from app.main import app, model_context, state
from app.schemas import ModelRun
from app.service import create, locked
from fastapi.testclient import TestClient


def test_exchange_is_not_in_global_polling_state_or_cloud_context():
    with locked() as session:
        target = create(session, "target", {"name": "fixture"})
        endpoint = create(
            session,
            "endpoint",
            {
                "target_id": target["id"],
                "method": "GET",
                "url": "https://fixture.example/private",
            },
        )
        model = create(session, "model", {"local": False})
        evidence = create(
            session,
            "evidence",
            {
                "target_id": target["id"],
                "http_exchange": {"response": {"body": "local-only-body-marker"}},
            },
        )
        _, context = model_context(
            session,
            target["id"],
            ModelRun(model_id=model["id"], endpoint_ids=[endpoint["id"]]),
        )
    response = state()
    row = next(e for e in response["evidence"] if e["id"] == evidence["id"])
    assert "http_exchange" not in row
    assert "local-only-body-marker" not in str(context)
    assert "https://fixture.example/private" not in str(context)


def test_catalog_requires_local_session_and_does_not_enable_planned_tests():
    client = TestClient(app)
    assert client.get("/api/test-catalog").status_code == 401
    response = client.get("/api/test-catalog", headers={"X-API-Key": "test-token"})
    assert response.status_code == 200
    assert len(response.json()["categories"]) == 18
    assert {t["id"] for t in response.json()["templates"]} == {
        "baseline",
        "role_compare",
        "both",
        "injection_errors",
        "xss_passive",
        "csrf_passive",
        "ssrf_passive",
        "xxe_passive",
        "file_passive",
        "deserialization_passive",
        "auth_session_passive",
        "disclosure_passive",
        "configuration_passive",
        "crypto_passive",
        "supply_chain_passive",
        "business_logic_review",
        "other_web_passive",
        "race_condition_review",
        "memory_safety_passive",
        "dos_passive",
        "cors_verify",
        "access_verify",
        "sql_error_verify",
        "xss_reflection_verify",
        "redirect_verify",
    }
