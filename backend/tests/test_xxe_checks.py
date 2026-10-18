import json

import pytest

from app.xxe_checks import inspect_response


@pytest.mark.parametrize("body", [
    'libxml warning: failed to load external entity "file:///private/secret"',
    'External entity access denied: https://private.invalid/key',
    'External parameter entity disabled',
    'accessExternalDTD property restriction',
    'lxml.etree.XMLSyntaxError: external entity cannot be loaded',
    '外部实体解析失败',
])
def test_parser_errors_are_only_unconfirmed_leads(body):
    checks, signals = inspect_response(body, {"Content-Type": "text/plain"})
    assert checks[0]["status"] == "hit"
    assert signals[0]["root"] == "xxe-parser-error"
    assert "待人工确认" in signals[0]["title"]
    assert "不能证明" in checks[0]["detail"]


@pytest.mark.parametrize("body", [
    '<!DOCTYPE root SYSTEM "https://private.invalid/dtd"><root/>',
    '<!DOCTYPE root PUBLIC "identifier" "https://private.invalid/dtd"><root/>',
    '<!DOCTYPE root [<!ENTITY resource SYSTEM "file:///private/secret">]><root>&resource;</root>',
    '<!ENTITY % external PUBLIC "id" "https://private.invalid/dtd">',
])
def test_external_declaration_is_review_only_and_never_expanded(body):
    checks, signals = inspect_response(body, {"content-type": "application/xml"})
    assert checks[1]["status"] == "inconclusive"
    assert not signals
    assert "声明本身不证明" in checks[1]["detail"]
    output = json.dumps([checks, signals])
    assert "private.invalid" not in output and "/private/secret" not in output


@pytest.mark.parametrize("body,mime", [
    ('<?xml version="1.0"?><root>ok</root>', "application/xml"),
    ('<!DOCTYPE root [<!ENTITY text "hello">]><root/>', "application/xml"),
    ('XMLSyntaxError: unexpected end tag', "text/plain"),
    ('SAXParseException: invalid XML', "text/plain"),
    ('Example: failed to load external entity', "text/plain"),
    ('文档：外部实体解析失败', "text/plain"),
    ('<pre>failed to load external entity</pre>', "text/html"),
    ('<code>failed to load external entity</code>', "text/html"),
    ('<script>"failed to load external entity"</script>', "text/html"),
    ('<template>failed to load external entity</template>', "text/html"),
    ('<!-- failed to load external entity -->', "text/html"),
    ('<!DOCTYPE html PUBLIC "normal" "https://private.invalid/dtd"><html/>', "application/xhtml+xml"),
])
def test_ordinary_xml_errors_and_examples_are_not_vulnerabilities(body, mime):
    checks, signals = inspect_response(body, {"content-type": mime})
    assert checks[0]["status"] == "not_detected"
    assert not signals


def test_visible_html_error_can_be_reviewed_without_raw_value_disclosure():
    checks, signals = inspect_response('<p>failed to load external entity file:///private/secret?token=abc</p>', {"content-type": "text/html"})
    assert signals
    assert "secret" not in json.dumps([checks, signals])


@pytest.mark.parametrize("mime", ["image/png", "application/octet-stream", "application/pdf", ""])
def test_non_text_is_not_applicable(mime):
    checks, signals = inspect_response('failed to load external entity', {"content-type": mime})
    assert all(c["status"] == "not_applicable" for c in checks)
    assert not signals


@pytest.mark.parametrize("body,headers", [(None, {}), (b"xml", {}), ("xml", None), ("xml", [])])
def test_malformed_input_is_inconclusive(body, headers):
    checks, signals = inspect_response(body, headers)
    assert all(c["status"] == "inconclusive" for c in checks)
    assert not signals


def test_large_and_malformed_text_is_bounded():
    checks, signals = inspect_response('<!DOCTYPE ' + 'x' * (1024 * 1024) + 'failed to load external entity', {"content-type": "application/xml"})
    assert all(c["status"] == "inconclusive" for c in checks)
    assert not signals


def test_malformed_html_and_header_keys_do_not_crash():
    checks, signals = inspect_response('<pre><code>failed to load external entity</pre><p>ok', {None: None, "Content-Type": "text/html"})
    assert not signals
    assert checks[0]["status"] == "not_detected"


def test_limits_and_allowed_statuses_are_explicit():
    checks, _ = inspect_response('ok', {"content-type": "application/problem+json"})
    for check in checks:
        assert check["status"] in {"hit", "not_detected", "not_applicable", "inconclusive", "not_run"}
        assert "不读取文件或回连" in check["detail"]
        assert "未命中不代表安全" in check["detail"]
