import json

import pytest

from app.crypto_checks import inspect_response

HEADERS = {"Content-Type": "text/plain"}


@pytest.mark.parametrize("body", ["hashlib.md5(password).hexdigest()", "password_hash = sha1(secret)", "DES.new(secret_key)", "AES.new(secret_key, MODE_ECB)", "requests.get(secret_url, verify=False)", "rejectUnauthorized: false", "ssl._create_unverified_context()", "CERTIFICATE_VERIFY_FAILED secret_url"])
def test_explicit_context_remains_unconfirmed(body):
    checks, signals = inspect_response(body, HEADERS)
    assert signals
    assert all(c["status"] in {"inconclusive", "not_detected"} for c in checks)
    output = json.dumps((checks, signals), ensure_ascii=False)
    assert body not in output
    assert "secret_url" not in output
    assert all("待人工确认" in s["title"] for s in signals)


@pytest.mark.parametrize("body", ["md5", "sha1 checksum", "hashlib.md5(asset_bytes)", "requests.get(url, verify=True)", "Documentation: requests.get(url, verify=False)", "AES.new(key, MODE_GCM)"])
def test_negative_or_document(body):
    assert not inspect_response(body, HEADERS)[1]


def test_binary_and_malformed():
    assert all(c["status"] == "not_applicable" for c in inspect_response("", {"content-type": "image/png"})[0])
    checks, signals = inspect_response(None, HEADERS)
    assert all(c["status"] == "inconclusive" for c in checks)
    assert not signals
