import json
import base64

import pytest

from app import business_logic_checks, other_web_checks, supply_chain_checks


HTML = {"Content-Type": "text/html; charset=utf-8"}


def test_supply_references_are_review_only_without_leaking_values():
    checks, signals = supply_chain_checks.inspect_response('<script src="http://private.invalid/lib-1.2.3.js?token=secret"></script>', HTML)
    assert [c["status"] for c in checks] == ["inconclusive"] * 3
    assert not signals
    assert "secret" not in json.dumps(checks)
    assert "不证明存在 CVE" in checks[2]["detail"]


def test_sri_is_a_review_hint_not_component_security_claim():
    digest = base64.b64encode(b"x" * 48).decode()
    checks, signals = supply_chain_checks.inspect_response(f'<script src="https://cdn.invalid/lib.js" integrity="sha384-{digest}"></script>', HTML)
    assert checks[0]["status"] == "not_detected"
    assert not signals
    assert "SRI 不保证组件安全" in checks[0]["detail"]


@pytest.mark.parametrize("integrity", ["sha384-YWJjZA==", "sha256-!!!!", "sha1-YWJjZA=="])
def test_invalid_integrity_digest_is_still_a_review_hint(integrity):
    checks, signals = supply_chain_checks.inspect_response(f'<script src="https://cdn.invalid/lib.js" integrity="{integrity}"></script>', HTML)
    assert checks[0]["status"] == "inconclusive"
    assert not signals


@pytest.mark.parametrize("body", ['<!-- <script src="http://x.invalid/a-1.2.js"> -->', '<template><script src="http://x.invalid/a-1.2.js"></script></template>', '<pre>&lt;script src="http://x.invalid/a-1.2.js"&gt;</pre>', '<script>const text = "1.2.3";</script>', '<img src="http://x.invalid/a-1.2.png">'])
def test_examples_and_ordinary_content_do_not_raise_supply_hints(body):
    checks, signals = supply_chain_checks.inspect_response(body, HTML)
    assert all(c["status"] == "not_detected" for c in checks)
    assert not signals


@pytest.mark.parametrize("name", ["price", "role", "owner_id", "payment_status", "step"])
def test_business_hidden_fields_never_become_findings(name):
    checks, signals = business_logic_checks.inspect_response(f'<form><input type="hidden" name="{name}" value="private"></form>', HTML)
    assert checks[0]["status"] == "inconclusive"
    assert not signals
    assert "private" not in json.dumps(checks)
    assert "资源归属" in checks[0]["detail"]


@pytest.mark.parametrize("body", ['<form><input name="price"></form>', '<form><input type="hidden" name="csrf_token"></form>', '<input type="hidden" name="price">', '<template><form><input type="hidden" name="price"></form></template>', '<!-- <form><input type="hidden" name="price"></form> -->'])
def test_generic_forms_are_not_business_logic_leads(body):
    checks, signals = business_logic_checks.inspect_response(body, HTML)
    assert checks[0]["status"] == "not_detected"
    assert not signals


def test_wildcard_credentials_is_invalid_combination_not_exploitable_finding():
    checks, signals = other_web_checks.inspect_response('', {**HTML, "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    assert checks[1]["status"] == "inconclusive"
    assert "浏览器拒绝" in checks[1]["detail"]
    assert not signals


@pytest.mark.parametrize("headers", [{"X-Frame-Options": "DENY"}, {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}])
def test_frame_policy_recognizes_headers(headers):
    checks, _ = other_web_checks.inspect_response('', {**HTML, **headers})
    assert checks[0]["status"] == "not_detected"


def test_report_only_csp_and_wildcard_ancestors_do_not_claim_protection():
    for headers in [{"Content-Security-Policy-Report-Only": "frame-ancestors 'none'"}, {"Content-Security-Policy": "frame-ancestors *"}]:
        checks, _ = other_web_checks.inspect_response('', {**HTML, **headers})
        assert checks[0]["status"] == "inconclusive"


def test_redirect_cannot_be_verified_without_status_or_input_context():
    checks, signals = other_web_checks.inspect_response('', {"Location": "https://private.invalid/path?token=secret", "Content-Type": "application/json"})
    assert checks[0]["status"] == "not_applicable"
    assert checks[2]["status"] == "inconclusive"
    assert not signals and "secret" not in json.dumps(checks)


@pytest.mark.parametrize("module", [supply_chain_checks, business_logic_checks, other_web_checks])
def test_invalid_input_and_malformed_html_remain_bounded(module):
    checks, signals = module.inspect_response(None, None)
    assert all(c["status"] == "inconclusive" for c in checks)
    assert not signals
    checks, signals = module.inspect_response('<form><input type="hidden" name="price"><script src="http://[bad">', HTML)
    assert not signals
    assert all(c["status"] in {"not_detected", "inconclusive"} for c in checks)


@pytest.mark.parametrize("module", [supply_chain_checks, business_logic_checks])
def test_non_html_is_not_applicable(module):
    checks, signals = module.inspect_response('<script src="http://x.invalid"></script>', {"content-type": "application/json"})
    assert all(c["status"] == "not_applicable" for c in checks)
    assert not signals
