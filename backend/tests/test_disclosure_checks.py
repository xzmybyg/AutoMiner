import json

import pytest

from app.disclosure_checks import inspect_response

HEADERS = {"Content-Type": "text/plain"}


@pytest.mark.parametrize("secret", ["AKIA" + "A" * 16, "ghp_" + "a" * 36, "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + "\n-----END PRIVATE KEY-----", 'password="sensitive-real-value"', "DB_PASSWORD=sensitive-real-value", "Traceback (most recent call last):"])
def test_positive_redacted(secret):
    checks, signals = inspect_response(secret, HEADERS)
    assert signals
    assert any(c["status"] == "hit" for c in checks)
    output = json.dumps((checks, signals), ensure_ascii=False)
    assert secret not in output
    assert "sensitive-real-value" not in output
    assert all("待人工确认" in s["title"] for s in signals)


@pytest.mark.parametrize("body", ['password="your_password_here"', 'api_key="example_key"', "AKIAshort", "ghp_short", "normal page", 'Documentation: password="sensitive-real-value"'])
def test_negative_or_document(body):
    checks, signals = inspect_response(body, HEADERS)
    assert not signals
    assert all(c["status"] == "not_detected" for c in checks)


def test_binary_and_malformed():
    assert all(c["status"] == "not_applicable" for c in inspect_response("", {"Content-Type": "image/png"})[0])
    checks, signals = inspect_response(None, HEADERS)
    assert all(c["status"] == "inconclusive" for c in checks)
    assert not signals
