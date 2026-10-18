import pytest

from app.xss_checks import inspect_response


def inspect(code, media="text/html"):
    return inspect_response(code, {"Content-Type": media})


@pytest.mark.parametrize("code,root", [
    ("<script>el.innerHTML = location.hash;</script>", "xss-dom-source-sink"),
    ("<script>document.write(window.location.search)</script>", "xss-dom-source-sink"),
    ("<script>el.insertAdjacentHTML('beforeend', document.referrer)</script>", "xss-dom-source-sink"),
    ("<button onclick=\"eval(location.hash)\">run</button>", "xss-dynamic-execution"),
    ("<script>setTimeout(location.search, 1)</script>", "xss-dynamic-execution"),
])
def test_executable_source_and_sink_leads(code, root):
    checks, signals = inspect(code)
    assert [s["root"] for s in signals] == [root]
    assert "待人工确认" in signals[0]["title"]
    assert next(c for c in checks if c["id"] == root)["status"] == "hit"


@pytest.mark.parametrize("code", [
    "<script>el.innerHTML = 'safe'; console.log(location.hash)</script>",
    "<script>el.innerHTML = trustedContent;</script>",
    "<script>// el.innerHTML = location.hash\nconsole.log('ok')</script>",
    "<script>/* eval(location.hash) */</script>",
    "<script>const example = 'el.innerHTML = location.hash';</script>",
    "<code>el.innerHTML = location.hash</code>",
    "<pre><script>eval(location.hash)</script></pre>",
    '<script type="application/json">{"example":"eval(location.hash)"}</script>',
    '<template><script>eval(location.hash)</script></template>',
    "<p>eval(location.hash)</p>",
])
def test_docs_comments_safe_values_and_unrelated_source_do_not_flag(code):
    checks, signals = inspect(code)
    assert not signals
    assert all(c["status"] == "not_detected" for c in checks[:2])


def test_javascript_response_and_untrusted_body_is_not_echoed():
    checks, signals = inspect("eval(location.hash); // secret-canary", "application/javascript; charset=utf-8")
    assert signals
    assert "secret-canary" not in str(checks) + str(signals)
    assert checks[-1]["status"] == "not_applicable"


@pytest.mark.parametrize("media", ["application/json", "text/plain", "image/svg+xml", ""])
def test_non_executable_media_is_explicitly_not_applicable(media):
    checks, signals = inspect("eval(location.hash)", media)
    assert not signals
    assert all(c["status"] == "not_applicable" for c in checks)


def test_csp_missing_is_unconfirmed_configuration_only():
    checks, signals = inspect("<h1>Hello</h1>")
    assert not signals
    assert checks[-1]["status"] == "inconclusive"
    for headers, body in [
        ({"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"}, ""),
        ({"content-type": "text/html"}, '<meta http-equiv="Content-Security-Policy" content="default-src self">'),
    ]:
        checks, signals = inspect_response(body, headers)
        assert checks[-1]["status"] == "inconclusive"
        assert "已观察到 CSP" in checks[-1]["detail"]
        assert not signals


@pytest.mark.parametrize("body", [
    "<meta http-equiv>",
    "<meta http-equiv=content-security-policy content>",
    "<script type>el.innerHTML = location.hash</script>",
    "<button onclick>button</button>",
])
def test_malformed_boolean_attributes_do_not_abort_analysis(body):
    checks, signals = inspect(body)
    assert len(checks) == 3
    assert checks[-1]["status"] == "inconclusive"


def test_large_response_is_bounded():
    checks, signals = inspect(" " * (1024 * 1024) + "eval(location.hash)", "application/javascript")
    assert not signals
    assert "1 MiB" in checks[0]["detail"]
