import json
import pytest
from app.ai_context import semantic_context, validate_assessments
from app.policy import Denied
from app.security import encrypt
from app.service import all_of, create, locked, get
from app.store import Session
from app import auto_scan
from test_auto_scan import ready, Reply, plan
from test_bounded_auto_scan import run_current_job, configure


def test_semantic_opt_in_redacts_and_scopes(monkeypatch):
    target, row, endpoint = ready(monkeypatch)
    with locked() as s:
        create(s, "account", dict(target_id=target["id"], role="reader", encrypted_headers=encrypt({"Authorization": "Bearer private-test-secret"})))
        item = create(s, "evidence", dict(target_id=target["id"], endpoint_id=endpoint["id"], job_id="included", state="complete", status=200,
            http_exchange={"response": {"body_state": "captured", "body": '{"token":"secret","email":"x@example.com","value":"Bearer private-test-secret"}', "truncated": True}}))
        create(s, "evidence", dict(target_id="other", endpoint_id=endpoint["id"], job_id="included", http_exchange={"response":{"body":"CROSS-TARGET"}}))
        context = semantic_context(s, target["id"], [endpoint], "Drafts are author only", ["included"])
    text = json.dumps(context)
    assert "private-test-secret" not in text and "x@example.com" not in text and "CROSS-TARGET" not in text
    assert context["interfaces"][0]["path"] == "/api/read"
    assert "app.example" not in text
    assert context["evidence"][0]["truncated"] is True
    assessment = dict(endpoint_id=endpoint["id"], evidence_ids=[item["id"]], hypothesis="Check draft ownership", observation="Insufficient evidence", missing_evidence="Two synthetic accounts")
    assert validate_assessments([assessment], {"semantic_context":context})[0]["status"] == "pending"
    with pytest.raises(Denied):
        validate_assessments([dict(assessment, evidence_ids=["invented"])], {"semantic_context":context})
    with pytest.raises(Denied):
        validate_assessments([assessment], {})


def test_auto_semantic_feedback_and_final_review_no_extra_requests(monkeypatch):
    target, row, endpoint = ready(monkeypatch)
    configure(row, include_semantic_context=True, max_rounds=1)
    calls = []
    class Response(Reply):
        def json(self):
            context = calls[-1]["context"]
            evidence = context["semantic_context"]["evidence"]
            return {"proposals": [] if context.get("review_only") else [plan(endpoint["id"])],
                "assessments":[dict(endpoint_id=endpoint["id"], evidence_ids=[e["evidence_id"] for e in evidence],
                    hypothesis="Check ownership", observation="Only anonymous response available", missing_evidence="Dedicated account comparison")]}
    def model(*args, **kwargs):
        calls.append(kwargs["json"])
        return Response([])
    monkeypatch.setattr(auto_scan.httpx, "post", model)
    auto_scan.advance()
    run_current_job(row, monkeypatch)
    auto_scan.advance()
    auto_scan.advance()
    with Session() as s:
        current = get(s, row["id"])
        assert current["review_status"] == "completed"
        assert current["used"] == 3
        assert len(current["job_ids"]) == 1
        assert current["assessments"][0]["evidence_ids"]
        assert all(f["status"] != "verified" for f in all_of(s, "finding"))
    assert len(calls) == 2
    assert sum(c["budget"] for c in calls) <= row["max_cost_usd"]
    assert calls[-1]["context"]["review_only"] is True


def test_manual_preview_is_opt_in_and_does_not_call_model(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    target, row, endpoint = ready(monkeypatch)
    def forbidden(*args, **kwargs):
        raise AssertionError("preview must not call a model")
    monkeypatch.setattr(auto_scan.httpx, "post", forbidden)
    client = TestClient(app)
    body = dict(model_id=row["model_id"], endpoint_ids=[endpoint["id"]], context="Drafts only visible to author")
    headers = {"X-API-Key":"test-token"}
    url = f"/api/targets/{target['id']}/model-preview"
    assert "semantic_context" not in client.post(url, json=body, headers=headers).json()["context"]
    result = client.post(url, json=dict(body, include_semantic_context=True), headers=headers)
    assert result.status_code == 200
    assert result.json()["context"]["semantic_context"]["interfaces"][0]["path"] == "/api/read"


def test_final_review_failure_not_retried(monkeypatch):
    target, row, endpoint = ready(monkeypatch)
    configure(row, include_semantic_context=True, max_rounds=1)
    calls = []
    def model(*args, **kwargs):
        calls.append(True)
        if len(calls) == 2:
            raise TimeoutError()
        return Reply([plan(endpoint["id"])])
    monkeypatch.setattr(auto_scan.httpx, "post", model)
    auto_scan.advance()
    run_current_job(row, monkeypatch)
    auto_scan.advance()
    auto_scan.advance()
    with Session() as s:
        assert get(s, row["id"])["review_status"] == "failed"
    assert len(calls) == 2
