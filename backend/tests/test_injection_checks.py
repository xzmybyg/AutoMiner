import pytest

from app.injection_checks import inspect_errors
from app.service import all_of, get, locked, process_job, save
from test_app import make_job, setup_target


@pytest.mark.parametrize("body,root", [
    ("You have an error in your SQL syntax", "database-error"),
    ("SQLSTATE[42000]", "database-error"),
    ("ERROR: syntax error at or near", "database-error"),
    ("jinja2.exceptions.TemplateSyntaxError: unexpected token", "template-error"),
    ("Twig\\Error\\SyntaxError", "template-error"),
    ("/bin/bash: line 1: syntax error near unexpected token", "command-parser-error"),
])
def test_specific_error_markers(body, root):
    checks, signals = inspect_errors(body)
    assert [s["root"] for s in signals] == [root]
    assert next(c for c in checks if c["id"] == root)["status"] == "hit"


@pytest.mark.parametrize("body", ["SQL injection guide", "template command syntax error", "正常页面", ""])
def test_generic_words_do_not_flag_injection(body):
    checks, signals = inspect_errors(body)
    assert not signals
    assert all(c["status"] == "not_detected" for c in checks)


def test_passive_template_keeps_request_and_links_pending_evidence(monkeypatch):
    target, endpoint = setup_target()
    job = make_job(target, endpoint, endpoint_test_types={endpoint["id"]: "injection_errors"})
    sent = []

    def response(target, url, headers, before_send):
        before_send()
        sent.append(url)
        return {"status": 500, "headers": {"content-type": "text/plain"},
                "body": "jinja2.exceptions.TemplateSyntaxError: unexpected token",
                "truncated": False}

    monkeypatch.setattr("app.service.request", response)
    process_job(job["id"])
    assert sent == [endpoint["url"]]
    with locked() as s:
        assert get(s, job["id"])["used"] == 1
        evidence = all_of(s, "evidence")
        assert len(evidence) == 1
        assert len(evidence[0]["checks"]) == 3
        findings = all_of(s, "finding")
        assert len(findings) == 1
        assert findings[0]["status"] == "pending"
        assert findings[0]["evidence_ids"] == [evidence[0]["id"]]
        assert "待人工确认" in findings[0]["title"]


@pytest.mark.parametrize("change", ["revoked", "budget", "stopped"])
def test_passive_template_still_blocks_before_network(monkeypatch, change):
    target, endpoint = setup_target()
    job = make_job(target, endpoint, endpoint_test_types={endpoint["id"]: "injection_errors"})
    with locked() as s:
        if change == "revoked":
            target["revoked"] = True
            save(s, target)
        else:
            job["used"] = job["request_budget"] if change == "budget" else 0
            if change == "stopped":
                job["status"] = "stopped"
            save(s, job)

    def forbidden(*args, **kwargs):
        pytest.fail("revoked, stopped or exhausted job must not send a request")

    monkeypatch.setattr("app.service.request", forbidden)
    process_job(job["id"])
    with locked() as s:
        assert not all_of(s, "evidence")
        assert not all_of(s, "finding")
