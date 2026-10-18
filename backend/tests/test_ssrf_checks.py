import json

import pytest

from app.ssrf_checks import inspect_response


@pytest.mark.parametrize("body", [
    "requests.exceptions.ConnectionError: connection failed",
    "urllib3.exceptions.MaxRetryError: retries exhausted",
    "httpx.ConnectTimeout: timed out",
    "GuzzleHttp\\Exception\\ConnectException: failed",
    "java.net.UnknownHostException: unavailable",
    "Outbound HTTP request blocked by policy",
    "服务端出站请求被拒绝",
])
def test_server_errors_are_unconfirmed_signals(body):
    checks, signals = inspect_response(body, {"Content-Type": "text/plain; charset=utf-8"})
    assert checks[0]["status"] == "hit"
    assert len(signals) == 1
    assert "待人工确认" in signals[0]["title"]


@pytest.mark.parametrize("body,mime", [
    ("fetch('https://example.test').catch(console.error)", "application/javascript"),
    ("Network error: connection refused", "text/plain"),
    ("Example: requests.exceptions.ConnectionError", "text/plain"),
    ("文档： httpx.ConnectTimeout", "text/html"),
    ("<pre>requests.exceptions.ConnectionError</pre>", "text/html"),
    ("<script>const x='httpx.ConnectError'</script>", "text/html"),
    ("<code>java.net.ConnectException</code>", "text/html"),
    ("Server unavailable", "text/plain"),
])
def test_generic_errors_javascript_and_examples_are_not_ssrf(body, mime):
    _, signals = inspect_response(body, {"content-type": mime})
    assert not signals


def test_url_field_only_prompts_review_and_never_discloses_response_values():
    body = '<form><input name="callback_url" value="http://10.0.0.1/?token=secret"></form>'
    checks, signals = inspect_response(body, {"content-type": "text/html"})
    assert checks[1]["status"] == "inconclusive"
    assert not signals
    result = json.dumps(checks, ensure_ascii=False)
    assert "10.0.0.1" not in result and "secret" not in result


def test_url_text_in_scripts_is_not_an_input():
    checks, _ = inspect_response('<script>"<input type=url>"</script>', {"content-type": "text/html"})
    assert checks[1]["status"] == "not_detected"


@pytest.mark.parametrize("mime", ["image/png", "application/octet-stream", ""])
def test_non_text_is_not_applicable(mime):
    checks, signals = inspect_response("httpx.ConnectError", {"content-type": mime})
    assert all(c["status"] == "not_applicable" for c in checks)
    assert not signals


def test_error_detail_uses_no_raw_body_or_destination():
    checks, signals = inspect_response('httpx.ConnectError: http://127.0.0.1/?token=secret', {"content-type": "application/json"})
    result = json.dumps([checks, signals], ensure_ascii=False)
    assert "127.0.0.1" not in result and "secret" not in result
    assert "未命中不代表安全" in result
