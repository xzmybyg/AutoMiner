import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.offline_review import ReviewInput, analyze, review
from app.service import all_of, create, locked
from app.job_management import job_detail


def data(**kwargs):
    return ReviewInput(materials_owned=True, **kwargs)


@pytest.mark.parametrize("category,content", [
    ("xss", "node.innerHTML = input"), ("configuration", "DEBUG = True"),
    ("upload", "upload.save(upload.filename)"), ("disclosure", 'api_key = "synthetic-private-secret"'),
    ("backdoor", "eval(request.args['value'])"), ("logic", "amount = req.body.amount"),
    ("code_execution", "eval(value)"), ("command_execution", "os.system(command)"),
    ("sql", 'cursor.execute(f"SELECT * FROM users WHERE id={value}")'),
    ("parser", "pickle.loads(value)")])
def test_source_categories(category, content):
    result = analyze(data(sources=[{"path": "test.txt", "content": content}]))
    assert any(i["category"] == category for i in result["items"])
    assert all(i["status"] == "lead" for i in result["items"])
    assert content not in json.dumps(result)


def test_weak_passwords_are_not_retained():
    result = analyze(data(passwords=["admin123", "123456", "jF8!sY2%wT9#rL6&qP4@zN7"]))
    assert len(result["items"]) == 2
    assert "admin123" not in json.dumps(result)
    assert result["materials"]["password_count"] == 3
    assert next(c for c in result["coverage"] if c["category"] == "incident")["status"] == "not_run"


def test_incident_correlations_and_window():
    events = [{"at": i, "kind": "login_failed", "actor": "private-actor"} for i in range(5)]
    result = analyze(data(events=events + [{"at": 6, "kind": "login_success", "actor": "private-actor"}]))
    assert {i["rule"] for i in result["items"]} == {"login-failure-burst", "success-after-failures"}
    assert "private-actor" not in json.dumps(result)
    events[-1]["at"] = 1000
    assert analyze(data(events=events))["items"] == []
    assert analyze(data(events=[{"at": i, "kind": "login_failed"} for i in range(6)]))["items"] == []


def test_integrity_and_indicators():
    baseline = [{"path": "app.py", "sha256": "a" * 64}, {"path": "old.py", "sha256": "b" * 64}]
    current = [{"path": "app.py", "sha256": "c" * 64}, {"path": "new.py", "sha256": "d" * 64}]
    result = analyze(data(baseline=baseline, current=current, known_bad_sha256=["d" * 64]))
    assert len(result["items"]) == 4
    assert all(i["status"] == "lead" for i in result["items"])
    assert analyze(data(current=current))["items"] == []
    assert analyze(data(baseline=baseline, current=baseline))["items"] == []


@pytest.mark.parametrize("kwargs", [{}, {"sources": [{"path": "../secret", "content": "x"}]},
    {"sources": [{"path": "C:/secret", "content": "x"}]}, {"passwords": ["x" * 257]},
    {"current": [{"path": "a", "sha256": "wrong"}]}, {"known_bad_sha256": ["wrong"], "passwords": ["x"]},
    {"sources": [{"path": "a", "content": "x"}, {"path": "a", "content": "y"}]}])
def test_input_boundaries(kwargs):
    with pytest.raises(ValidationError):
        data(**kwargs)


def test_comment_and_safe_parameterized_control():
    result = analyze(data(sources=[{"path": "app.py", "content": '# eval(request.args["x"])\ncursor.execute("SELECT * FROM users WHERE id = ?", (value,))'}]))
    assert result["items"] == []
    assert next(c for c in result["coverage"] if c["category"] == "sql")["status"] == "reviewed"


def test_byte_limits_and_bounded_results():
    with pytest.raises(ValidationError):
        data(sources=[{"path": "a.txt", "content": "中" * 100000}])
    with pytest.raises(ValidationError):
        data(sources=[{"path": str(i) + ".txt", "content": "x" * 250001} for i in range(8)])
    result = analyze(data(sources=[{"path": "a.py", "content": "eval(value)\n" * 201 + "DEBUG = True"}]))
    assert len(result["items"]) == 200
    assert next(c for c in result["coverage"] if c["category"] == "configuration")["status"] == "lead"
    assert "省略 2 条" in result["limitations"]


def test_persistent_task_evidence_report_scope_and_no_traffic(monkeypatch):
    import app.service as service
    monkeypatch.setattr(service, "request", lambda *a, **k: pytest.fail("Offline review must not send traffic"))
    with locked() as s:
        target = create(s, "target", {"name": "test", "kind": "src", "version": 2})
    result = review(target["id"], data(passwords=["admin123"], sources=[{"path": "a.py", "content": 'api_key="synthetic-private-secret"'}]))
    detail = job_detail(result["job_id"])
    assert detail["coverage"]["sent_requests"] == detail["coverage"]["completed_requests"] == 0
    assert len(detail["findings"]) == 2
    with locked() as s:
        persisted = json.dumps(all_of(s, "job") + all_of(s, "evidence") + all_of(s, "finding") + all_of(s, "audit"))
    assert "admin123" not in persisted and "synthetic-private-secret" not in persisted
    client = TestClient(app)
    assert client.post(f'/api/targets/{target["id"]}/offline-reviews', json={"passwords": ["x"], "materials_owned": True}).status_code == 401
    invalid = client.post(f'/api/targets/{target["id"]}/offline-reviews', headers={"X-API-Key": "test-token"}, json={"passwords": ["private-test-password"], "materials_owned": False})
    assert invalid.status_code == 422 and "private-test-password" not in invalid.text
