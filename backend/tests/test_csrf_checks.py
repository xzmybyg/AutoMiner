import json

import pytest

from app.csrf_checks import inspect_response


def test_post_form_missing_token_is_only_pending_clue():
    checks, signals = inspect_response('<form method="POST"><input name="email" value="private@example.org"></form>', {"Content-Type": "text/html"})
    assert checks[0]["status"] == "inconclusive"
    assert [s["root"] for s in signals] == ["csrf-form-token-clue"]
    assert "private@example.org" not in json.dumps((checks, signals))
    assert "缺少字段不证明" in checks[0]["detail"]


@pytest.mark.parametrize("body", [
    '<form method="post"><input type="hidden" name="csrf_token" value="secret"></form>',
    '<form method="post"><input type="hidden" name="__RequestVerificationToken" value="secret"></form>',
    '<form><input name="query"></form>',
    '<p>No forms</p>',
])
def test_token_or_get_form_does_not_claim_safe(body):
    checks, signals = inspect_response(body, {"content-type": "text/html"})
    assert checks[0]["status"] == "inconclusive"
    assert not signals
    assert "secret" not in json.dumps((checks, signals))


def test_malformed_and_external_form_association_are_inconclusive():
    for body in ['<form method="post">', '<form method="post"><input form="other"></form>', '<form><form method="post"></form></form>', '<form method="unknown"></form>', '<form><input formmethod="post"></form>']:
        checks, signals = inspect_response(body, {"content-type": "text/html"})
        assert checks[0]["status"] == "inconclusive"
        assert "歧义" in checks[0]["detail"]
        assert not signals


@pytest.mark.parametrize("same_site", ["Strict", "Lax"])
def test_cookie_defence_is_not_a_verified_pass(same_site):
    checks, signals = inspect_response('{}', {"CONTENT-TYPE": "application/json", "SET-COOKIE": f"session=secret; SameSite={same_site}; HttpOnly"})
    assert checks[0]["status"] == "not_applicable"
    assert checks[1]["status"] == "inconclusive"
    assert not signals
    assert "secret" not in json.dumps(checks)


def test_folded_cookie_expires_and_list_headers():
    for value in [
        "session=secret; Expires=Wed, 21 Oct 2030 07:28:00 GMT, auth_token=private; SameSite=None; Secure",
        ["session=secret; Path=/", "auth_token=private; SameSite=None; Secure"],
    ]:
        checks, signals = inspect_response('', {"set-cookie": value})
        assert "2 个疑似会话" in checks[1]["detail"]
        assert "1 个未显式" in checks[1]["detail"]
        assert "1 个声明 SameSite=None" in checks[1]["detail"]
        assert [s["root"] for s in signals] == ["csrf-cookie-policy-clue"]
        assert "secret" not in json.dumps((checks, signals))
        assert "private" not in json.dumps((checks, signals))


@pytest.mark.parametrize("value", ['session="secret,other=value"', "invalid cookie", "session=x; SameSite=invalid"])
def test_ambiguous_cookie_does_not_invent_a_finding(value):
    checks, signals = inspect_response('', {"set-cookie": value})
    assert "无法确定" in checks[1]["detail"]
    assert not signals


def test_csrf_cookie_is_not_misidentified_as_auth_cookie():
    checks, signals = inspect_response('', {"set-cookie": "csrftoken=secret"})
    assert not signals
    assert "0 个疑似会话" in checks[1]["detail"]
