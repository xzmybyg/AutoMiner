import json

import pytest

from app.file_checks import inspect_response


@pytest.mark.parametrize("body", [
    "FileNotFoundError: private path", "PermissionError: access denied",
    "java.io.FileNotFoundException: private path", "System.IO.PathTooLongException: private path",
    "Warning: include(private): Failed to open stream: No such file or directory",
    "Warning: require_once(private): Failed opening required file",
    "ENOENT: no such file or directory, open 'private'",
])
def test_explicit_file_errors_need_manual_confirmation(body):
    checks, signals = inspect_response(body, {"Content-Type": "text/plain"})
    assert checks[0]["status"] == "hit"
    assert len(signals) == 1 and "待人工确认" in signals[0]["title"]
    assert "private" not in json.dumps([checks, signals])


@pytest.mark.parametrize("body", [
    "file not found", "404 not found", "ENOENT", "Error: open failed",
    "Example: FileNotFoundError: private", "文档： PermissionError: private",
    "<pre>FileNotFoundError: private</pre>",
    "<script>const x='PermissionError: private'</script>",
    "<code>java.io.FileNotFoundException: private</code>",
    "<pre><code>PermissionError: private</code></pre>",
    "<pre>hidden</code>PermissionError: private</pre>",
])
def test_generic_errors_and_examples_are_not_findings(body):
    checks, signals = inspect_response(body, {"content-type": "text/html"})
    assert checks[0]["status"] == "not_detected"
    assert not signals


@pytest.mark.parametrize("field", ['type="file"', 'name="download_path"', 'name="filename"'])
def test_file_fields_are_review_only(field):
    checks, signals = inspect_response(f'<input {field} value="secret">', {"content-type": "text/html"})
    assert checks[1]["status"] == "inconclusive"
    assert not signals
    assert "secret" not in json.dumps(checks)


def test_hidden_inputs_and_malformed_markup_are_safe():
    checks, signals = inspect_response('<script><input type=file></script><pre><input type=file>', {"content-type": "text/html"})
    assert checks[1]["status"] == "not_detected"
    assert not signals


@pytest.mark.parametrize("mime", ["image/png", "application/octet-stream", ""])
def test_nontext_is_not_applicable(mime):
    checks, signals = inspect_response("FileNotFoundError: private", {"Content-Type": mime})
    assert all(c["status"] == "not_applicable" for c in checks)
    assert not signals


def test_json_errors_have_no_form_applicability():
    checks, signals = inspect_response('{"error":"FileNotFoundError: private"}', {"CONTENT-TYPE": "application/problem+json"})
    assert checks[0]["status"] == "hit"
    assert checks[1]["status"] == "not_applicable"
    assert signals
