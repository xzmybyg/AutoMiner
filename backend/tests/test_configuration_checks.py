import json

import pytest

from app.configuration_checks import inspect_response

HTML = {"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"}


def test_directory_requires_html_marker_and_links():
    checks, signals = inspect_response('<h1>Index of /private</h1><a href="sensitive-file">file</a>', HTML)
    assert checks[0]["status"] == "hit"
    assert signals[0]["root"] == "configuration-directory-index"
    assert "sensitive-file" not in json.dumps((checks, signals))
    assert inspect_response('<h1>Index of /</h1>', HTML)[0][0]["status"] == "not_detected"


@pytest.mark.parametrize("body", ["DEBUG=True", '{"DEBUG":true}', "Werkzeug Debugger"])
def test_explicit_debug(body):
    assert inspect_response(body, HTML)[0][1]["status"] == "hit"


def test_defense_headers_only_configuration_review():
    checks, signals = inspect_response("normal", {"content-type": "text/html", "server": "nginx/1.2.3"})
    assert checks[2]["status"] == "inconclusive"
    assert checks[3]["status"] == "inconclusive"
    assert "缺少头不等于漏洞" in checks[3]["detail"]
    assert signals == [{"root": "configuration-defense-headers", "title": "浏览器防护头配置待复核，待人工确认"}]


def test_docs_binary_and_malformed():
    assert not inspect_response("Documentation DEBUG=True", HTML)[1]
    assert not inspect_response("DEBUG=True", {"content-type": "image/png"})[1]
    checks, signals = inspect_response(None, HTML)
    assert checks[0]["status"] == "inconclusive"
    assert not signals
