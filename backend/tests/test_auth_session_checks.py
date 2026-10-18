import json

import pytest

from app.auth_session_checks import inspect_response


def test_missing_flags_are_pending_configuration_only():
    checks, signals = inspect_response('', {"Set-Cookie": "session_secret=private-token; Path=/"})
    assert checks[0]["status"] == "inconclusive"
    assert signals[0]["root"] == "auth-session-cookie-config-clue"
    assert "HTTP 本地开发环境" in checks[0]["detail"]
    assert "不能直接判为漏洞" in checks[0]["detail"]
    serialized = json.dumps((checks, signals), ensure_ascii=False)
    assert "private-token" not in serialized
    assert "session_secret" not in serialized


def test_complete_cookie_does_not_claim_security():
    checks, signals = inspect_response('', {"set-cookie": "session=secret; HttpOnly; Secure; SameSite=Lax"})
    assert not signals
    assert checks[0]["status"] == "inconclusive"
    assert "属性存在不证明" in checks[0]["detail"]


def test_individual_cookie_headers_and_expires():
    checks, signals = inspect_response('', {"SET-COOKIE": [
        "session=private-one; Expires=Wed, 21 Oct 2030 07:28:00 GMT; HttpOnly; Secure; SameSite=Strict",
        "access_token=private-two; HttpOnly; SameSite=None",
    ]})
    assert "2 个疑似" in checks[0]["detail"]
    assert "1 个声明 SameSite=None" in checks[0]["detail"]
    assert len(signals) == 1
    assert "private-" not in json.dumps((checks, signals))


@pytest.mark.parametrize("value", [
    "session=secret, auth=other", "session=secret; Expires=Wed, 21 Oct 2030 07:28:00 GMT, sid=other",
    "session=secret\r\nSet-Cookie: auth=other", 'session="secret,other=value"',
    "invalid cookie", "session=secret; SameSite=bogus", "session=x; Secure=false",
    "session=x; HttpOnly=0", "session=x; SameSite=Lax; SameSite=None", None, "",
])
def test_ambiguous_cookie_suppresses_configuration_signal(value):
    checks, signals = inspect_response('', {"set-cookie": ["session=secret", value]})
    assert checks[0]["status"] == "inconclusive"
    assert "整体无法确定" in checks[0]["detail"]
    assert not signals


@pytest.mark.parametrize("name", ["theme", "csrftoken", "xsrf_session", "author", "analytics"])
def test_does_not_assume_every_cookie_is_session(name):
    checks, signals = inspect_response('', {"set-cookie": f"{name}=private"})
    assert "0 个疑似" in checks[0]["detail"]
    assert checks[0]["status"] == "inconclusive"
    assert not signals


def test_basic_is_pending_and_does_not_retain_challenge_parameters():
    checks, signals = inspect_response('private-body', {"WWW-Authenticate": 'Basic realm="private-realm"'})
    assert checks[1]["status"] == "inconclusive"
    assert signals == [{"root": "auth-session-basic-clue", "title": "HTTP Basic 认证配置线索，待人工确认"}]
    assert "没有请求协议上下文" in checks[1]["detail"]
    assert "private" not in json.dumps((checks, signals))


def test_bearer_and_missing_header_do_not_claim_safe():
    checks, signals = inspect_response('', {"WWW-Authenticate": 'Bearer error="private"'})
    assert checks[1]["status"] == "inconclusive"
    assert not signals
    checks, signals = inspect_response('', {})
    assert [c["status"] for c in checks] == ["not_applicable", "not_detected"]
    assert not signals


@pytest.mark.parametrize("challenge", ['Bearer realm="private,Basic text"', 'Bearer realm="private,Basic text'])
def test_basic_text_inside_realm_is_not_auth_scheme(challenge):
    checks, signals = inspect_response('', {"www-authenticate": challenge})
    assert checks[1]["status"] == "inconclusive"
    assert not signals
