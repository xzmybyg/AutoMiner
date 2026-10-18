import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import auto_scan
from app.main import app
from app.service import all_of, get, locked, process_job, save
from app.store import Session, now
from test_auto_scan import Reply, plan, ready


def configure(row, **changes):
    with locked() as s:
        current = get(s, row["id"])
        current.update(changes)
        save(s, current)


def run_current_job(row, monkeypatch, fail=False):
    with locked() as s:
        current = get(s, row["id"])
        job = get(s, current["job_id"])
        job.update(status="running", deadline=now() + 60)
        save(s, job)
    def transport(target, url, headers, before_send):
        before_send()
        if fail:
            raise TimeoutError("synthetic failure")
        return {"status": 200, "headers": {"Content-Type": "text/html", "X-Private": "DO-NOT-SEND-HEADER"},
                "body": "<html>DO-NOT-SEND-BODY</html>", "truncated": False}
    monkeypatch.setattr("app.service.request", transport)
    process_job(job["id"])
    return job["id"]


def test_two_round_feedback_is_bounded_redacted_and_reports_all_jobs(monkeypatch):
    _, row, endpoint = ready(monkeypatch)
    configure(row, allowed_test_types=["baseline", "configuration_passive"])
    contexts, budgets = [], []
    def model(*args, **kwargs):
        contexts.append(kwargs["json"]["context"])
        budgets.append(kwargs["json"]["budget"])
        proposal = plan(endpoint["id"])
        proposal.update(test_type="baseline" if len(contexts) == 1 else "configuration_passive",
                        expected_evidence="api_key='synthetic-plan-secret'")
        return Reply([proposal])
    monkeypatch.setattr(auto_scan.httpx, "post", model)
    auto_scan.advance()
    first_job = run_current_job(row, monkeypatch)
    auto_scan.advance()
    second_job = run_current_job(row, monkeypatch)
    auto_scan.advance()
    with Session() as s:
        current = get(s, row["id"])
        assert current["status"] == "completed"
        assert len(current["rounds"]) == 2
        assert current["job_ids"] == [first_job, second_job]
        assert current["used"] == 4 <= current["request_budget"]
        assert sum(budgets) <= current["max_cost_usd"]
        assert current["model_budget_reserved"] <= current["max_cost_usd"]
        assert "synthetic-plan-secret" not in str(current)
        report = get(s, current["report_id"], "report")
        assert first_job in report["content"] and second_job in report["content"]
    assert contexts[1]["feedback"][0]["completed_requests"] == 1
    for forbidden in ("app.example", "DO-NOT-SEND-BODY", "DO-NOT-SEND-HEADER", "synthetic-plan-secret"):
        assert forbidden not in json.dumps(contexts)
    client = TestClient(app)
    assert client.get(f"/api/auto-scans/{row['id']}/report").status_code == 401
    response = client.get(f"/api/auto-scans/{row['id']}/report", headers={"X-API-Key": "test-token"})
    assert response.status_code == 200
    assert first_job in response.text and second_job in response.text


def test_repeated_plan_never_replays_requests(monkeypatch):
    _, row, endpoint = ready(monkeypatch)
    configure(row, allowed_test_types=["baseline", "configuration_passive"])
    calls = []
    def model(*args, **kwargs):
        calls.append(True)
        return Reply([plan(endpoint["id"])])
    monkeypatch.setattr(auto_scan.httpx, "post", model)
    auto_scan.advance()
    run_current_job(row, monkeypatch)
    auto_scan.advance()
    auto_scan.advance()
    with Session() as s:
        current = get(s, row["id"])
        assert current["status"] == "completed"
        assert len(current["job_ids"]) == 1
        assert "重复" in current["stop_reason"]
        assert len(all_of(s, "evidence")) == 1
    assert len(calls) == 2


@pytest.mark.parametrize("changes,fail", [({"request_budget": 3}, False), ({"max_rounds": 1}, False), ({}, True)])
def test_budget_round_limit_or_no_progress_stops_before_another_paid_call(monkeypatch, changes, fail):
    _, row, endpoint = ready(monkeypatch)
    configure(row, allowed_test_types=["baseline", "configuration_passive"], **changes)
    calls = []
    def model(*args, **kwargs):
        calls.append(True)
        return Reply([plan(endpoint["id"])])
    monkeypatch.setattr(auto_scan.httpx, "post", model)
    auto_scan.advance()
    run_current_job(row, monkeypatch, fail=fail)
    auto_scan.advance()
    with Session() as s:
        current = get(s, row["id"])
        assert current["status"] == "completed"
        assert current["used"] <= current["request_budget"]
        assert len(current["job_ids"]) == 1
    assert len(calls) == 1


def test_concurrent_tick_cannot_duplicate_model_call(monkeypatch):
    _, row, endpoint = ready(monkeypatch)
    calls = []
    def model(*args, **kwargs):
        calls.append(True)
        auto_scan.advance()
        return Reply([plan(endpoint["id"])])
    monkeypatch.setattr(auto_scan.httpx, "post", model)
    auto_scan.advance()
    with Session() as s:
        assert len(all_of(s, "job")) == 1
        assert len(get(s, row["id"])["rounds"]) == 1
    assert len(calls) == 1


@pytest.mark.parametrize("templates", [["arbitrary_command"], ["access_verify"], ["role_compare"], []])
def test_auto_template_selection_is_a_deterministic_allowlist(templates):
    with pytest.raises(ValidationError):
        auto_scan.AutoInput(target_id="target", model_id="model", allowed_test_types=templates)


def test_wrong_active_request_cost_is_rejected_before_creating_job(monkeypatch):
    _, row, endpoint = ready(monkeypatch)
    configure(row, allowed_test_types=["cors_verify"])
    proposal = plan(endpoint["id"])
    proposal["test_type"] = "cors_verify"
    monkeypatch.setattr(auto_scan.httpx, "post", lambda *a, **k: Reply([proposal]))
    auto_scan.advance()
    with Session() as s:
        assert get(s, row["id"])["status"] == "blocked"
        assert not all_of(s, "job")


def test_empty_model_plan_produces_explicit_no_coverage_report(monkeypatch):
    _, row, _ = ready(monkeypatch)
    monkeypatch.setattr(auto_scan.httpx, "post", lambda *a, **k: Reply([]))
    auto_scan.advance()
    with Session() as s:
        current = get(s, row["id"])
        assert current["status"] == "completed" and not current["job_ids"]
        snapshot = get(s, current["report_id"])
        assert "没有检测证据" in snapshot["content"]
