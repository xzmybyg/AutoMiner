import json

import pytest

from app.race_condition_checks import inspect_response


@pytest.mark.parametrize("body", ['DeadlockDetected: secret', 'SQLSTATE[40001]: serialization failure', 'could not serialize access due to concurrent update', 'javax.persistence.OptimisticLockException'])
def test_diagnostic_is_unconfirmed_and_does_not_copy_secrets(body):
    checks, signals = inspect_response(body + " /private/token 0x123abc secret-value", {"Content-Type": "text/plain"})
    assert checks[0]["status"] == "hit"
    assert signals and "待人工确认" in signals[0]["title"]
    assert "不能证明" in checks[0]["detail"] or "不能确认" in checks[0]["detail"]
    output = json.dumps([checks, signals])
    assert "secret-value" not in output and "0x123abc" not in output and "/private/token" not in output


@pytest.mark.parametrize("body", ["ok", "segfault", "out of memory", "429 Too Many Requests", "409 Conflict", "123456", "AddressSanitizer", "race condition", "deadlock", "time limit"])
def test_generic_words_are_not_vulnerability_evidence(body):
    checks, signals = inspect_response(body, {"content-type": "text/plain"})
    assert checks[0]["status"] == "not_detected"
    assert not signals and "未命中不代表安全" in checks[0]["detail"]


@pytest.mark.parametrize("wrapper,mime", [("`{}`", "text/plain"), ("<pre>{}</pre>", "text/html"), ("<code>{}</code>", "text/html"), ("<script>{}</script>", "text/html"), ("<!-- {} -->", "text/html"), ("Documentation: {}", "text/plain"), ("```text\n{}\n```", "text/plain")])
def test_examples_are_ignored(wrapper, mime):
    checks, signals = inspect_response(wrapper.format('DeadlockDetected: secret'), {"content-type": mime})
    assert checks[0]["status"] == "not_detected" and not signals


def test_visible_html_error():
    checks, signals = inspect_response("<p>" + 'DeadlockDetected: secret' + "</p>", {"content-type": "text/html"})
    assert checks[0]["status"] == "hit" and signals


@pytest.mark.parametrize("body,headers,status", [(None, {}, "inconclusive"), ("ok", None, "inconclusive"), ("ok", [], "inconclusive"), ("ok", {}, "not_applicable"), ("ok", {"content-type": "image/png"}, "not_applicable"), ("ok", {1: None}, "not_applicable")])
def test_malformed_or_nontext_data(body, headers, status):
    checks, signals = inspect_response(body, headers)
    assert checks[0]["status"] == status and not signals


def test_truncated_response_is_inconclusive():
    checks, signals = inspect_response("x" * (1024 * 1024 + 1), {"content-type": "text/plain"})
    assert checks[0]["status"] == "inconclusive" and not signals
