import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import main, task_monitor as monitor
from app.service import all_of, audit, create, get, locked, save


def seed(monkeypatch, status="running"):
    monkeypatch.setenv("MODEL_GATEWAY_URL", "http://model-outlet")
    with locked() as s:
        target = create(s, "target", {"name": "private target"})
        model = create(s, "model", {"name": "local", "local": True})
        job = create(s, "job", {"target_id": target["id"], "status": status, "used": 1, "request_budget": 5})
        other = create(s, "job", {"target_id": target["id"], "status": "running"})
        audit(s, "job_started", job["id"], "secret Cookie bearer token")
        audit(s, "job_started", other["id"], "unrelated secret")
        create(s, "evidence", {"job_id": job["id"], "state": "complete", "body": "secret", "url": "secret"})
    row = monitor.configure(job["id"], monitor.Settings(enabled=True, model_id=model["id"]))
    return job, model, row


def reply(monkeypatch, callback=None, result=None):
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        if callback:
            callback()

        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                return result or {"summary": "任务正在运行，请等待结果。"}

        return Response()

    monkeypatch.setattr(monitor.httpx, "post", post)
    return calls


def test_private_task_scoped_observer_and_persistence(monkeypatch):
    job, model, row = seed(monkeypatch)
    calls = reply(monkeypatch)
    monitor.observe(row["id"])
    result = monitor.read(job["id"])
    assert result["calls"] == 1 and result["entries"]
    context = calls[0][1]["json"]["context"]
    assert context["event_count"] == 1
    assert context["completed_requests"] == 1
    assert "secret" not in json.dumps(context)
    assert calls[0][0] == "http://model-outlet/internal/model"
    with locked() as s:
        assert len(all_of(s, "job")) == 2  # Never creates execution work.
    monitor.observe(row["id"])
    assert len(calls) == 1  # Unchanged events do not cause repeated calls.
    monitor.configure(job["id"], monitor.Settings(enabled=False))
    monitor.observe(row["id"])
    assert len(calls) == 1
    assert monitor.read(job["id"])["calls"] == 1


def test_disable_discards_inflight_result(monkeypatch):
    job, _, row = seed(monkeypatch)
    reply(monkeypatch, lambda: monitor.configure(job["id"], monitor.Settings(enabled=False)))
    monitor.observe(row["id"])
    result = monitor.read(job["id"])
    assert not result["enabled"] and result["entries"] == []
    assert result["calls"] == 1 and result["reserved_usd"] > 0


def test_limit_survives_toggle(monkeypatch):
    job, model, row = seed(monkeypatch)
    calls = reply(monkeypatch)
    for i in range(3):
        with locked() as s:
            current = get(s, row["id"])
            current["last_call_at"] = 0
            save(s, current)
            audit(s, "request_finished", job["id"])
        monitor.observe(row["id"])
    monitor.observe(row["id"])
    assert len(calls) == 3
    assert monitor.read(job["id"])["state"] == "limit"
    with pytest.raises(HTTPException):
        monitor.configure(job["id"], monitor.Settings(enabled=True, model_id=model["id"]))


@pytest.mark.parametrize("result", [{"summary": "text", "tools": ["scan"]}, {"summary": "x" * 801}])
def test_invalid_model_output_stops_only_observer(monkeypatch, result):
    job, _, row = seed(monkeypatch)
    reply(monkeypatch, result=result)
    monitor.observe(row["id"])
    assert monitor.read(job["id"])["state"] == "error"
    with locked() as s:
        assert get(s, job["id"])["status"] == "running"


def test_terminal_task_automatically_stops(monkeypatch):
    job, _, row = seed(monkeypatch, "completed")
    reply(monkeypatch)
    monitor.observe(row["id"])
    assert monitor.read(job["id"])["state"] == "finished"
    assert not monitor.read(job["id"])["enabled"]


def test_api_auth_and_default_off(monkeypatch):
    job, _, _ = seed(monkeypatch)
    client = TestClient(main.app)
    assert client.get(f'/api/jobs/{job["id"]}/monitor').status_code == 401
    with locked() as s:
        fresh = create(s, "job", {"target_id": job["target_id"], "status": "queued"})
    response = client.get(f'/api/jobs/{fresh["id"]}/monitor', headers={"X-API-Key": "test-token"})
    assert response.json()["enabled"] is False


def test_model_gateway_uses_observer_prompt(monkeypatch):
    _, model, _ = seed(monkeypatch)
    monkeypatch.setattr(main, "ROLE", "model")
    with locked() as s:
        row = get(s, model["id"])
        row["max_output_tokens"] = 500
        save(s, row)
    prompts = []
    monkeypatch.setattr(main, "completion", lambda model, prompt: prompts.append(prompt) or {"summary": "观察"})
    main.model_call({"model_id": model["id"], "planning_mode": "task_monitor", "context": {"status": "running"}, "budget": .03})
    assert "read-only event observer" in prompts[0]
    assert "proposals" not in prompts[0]


def test_logical_task_includes_children_but_not_same_target_jobs(monkeypatch):
    job, _, _ = seed(monkeypatch)
    with locked() as s:
        root = create(s, "scan_run", {"target_id": job["target_id"], "job_ids": [job["id"]], "discovery_ids": []})
        context = monitor.snapshot(s, root["id"])
    assert context["event_count"] == 1
    assert context["completed_requests"] == 1


def test_changed_events_respect_interval(monkeypatch):
    job, _, row = seed(monkeypatch)
    calls = reply(monkeypatch)
    monitor.observe(row["id"])
    with locked() as s:
        audit(s, "request_finished", job["id"])
    monitor.observe(row["id"])
    assert len(calls) == 1


def test_timeout_stops_observer_without_leaking_error(monkeypatch):
    job, _, row = seed(monkeypatch)
    def timeout(*args, **kwargs):
        raise RuntimeError("private credential")
    monkeypatch.setattr(monitor.httpx, "post", timeout)
    monitor.observe(row["id"])
    result = monitor.read(job["id"])
    assert not result["enabled"]
    assert "private credential" not in json.dumps(result)
    assert result["reserved_usd"] > 0
