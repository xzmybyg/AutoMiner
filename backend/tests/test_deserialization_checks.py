import json

import pytest

from app.deserialization_checks import inspect_response


@pytest.mark.parametrize("body", [
    "java.io.InvalidClassException: private", "java.io.StreamCorruptedException: private",
    "java.io.InvalidObjectException: private", "java.io.OptionalDataException: private",
    "com.fasterxml.jackson.databind.exc.InvalidTypeIdException: private",
    "unserialize(): Error at offset 1 of 20 bytes",
    "unserialize(): Unexpected end of serialized data",
    "_pickle.UnpicklingError: private", "pickle.UnpicklingError: private",
    "System.Runtime.Serialization.SerializationException: private",
    "Newtonsoft.Json.JsonSerializationException: private",
])
def test_explicit_errors_are_only_unconfirmed_signals(body):
    checks, signals = inspect_response(body, {"Content-Type": "text/plain; charset=utf-8"})
    assert checks[0]["status"] == "hit"
    assert len(signals) == 1 and "待人工确认" in signals[0]["title"]
    assert "private" not in json.dumps([checks, signals])


@pytest.mark.parametrize("body", [
    "Invalid data", "JSONDecodeError: invalid syntax", "unserialize() is disabled",
    "pickle data", "java.lang.ClassNotFoundException: private",
    "Example: _pickle.UnpicklingError: private", "教程： java.io.InvalidClassException: private",
    "<code>java.io.StreamCorruptedException: private</code>",
    "<pre><code>pickle.UnpicklingError: private</code></pre>",
    "<script>const error='unserialize(): Error at offset 1'</script>",
    "<pre>hidden</code>pickle.UnpicklingError: private</pre>",
])
def test_examples_and_unrelated_errors_are_not_findings(body):
    checks, signals = inspect_response(body, {"content-type": "text/html"})
    assert checks[0]["status"] == "not_detected"
    assert not signals


@pytest.mark.parametrize("mime", ["image/png", "application/octet-stream", "application/x-java-serialized-object", ""])
def test_serialized_binary_is_not_decoded(mime):
    checks, signals = inspect_response("pickle.UnpicklingError: private", {"content-type": mime})
    assert checks[0]["status"] == "not_applicable"
    assert not signals


def test_malformed_html_and_json_are_not_loaded_as_objects():
    checks, signals = inspect_response('<code><pre>pickle.UnpicklingError: private</code>', {"content-type": "text/html"})
    assert not signals
    checks, signals = inspect_response('{"error":"_pickle.UnpicklingError: private"', {"content-type": "application/json"})
    assert checks[0]["status"] == "hit"
    assert signals
    assert "未命中不代表安全" in checks[0]["detail"]
