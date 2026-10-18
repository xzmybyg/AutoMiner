import pytest

from app.security import capture_text, http_exchange, redact


@pytest.mark.parametrize("credential", ["AKIA" + "A" * 16, "ASIA" + "B" * 16, "ghp_" + "c" * 36])
def test_recognized_bare_credentials_are_redacted_in_evidence(credential):
    body = "<p>" + credential + "</p>"
    assert credential not in redact(body)
    assert credential not in capture_text('{"message":"' + credential + '"}')
    evidence = http_exchange("http://localhost:5177/", {
        "status": 200, "headers": {"Content-Type": "text/html"},
        "body": body, "truncated": False,
    })
    assert credential not in str(evidence)
    assert "CREDENTIAL REDACTED" in str(evidence)


@pytest.mark.parametrize("field", ["DATABASE_URL", "SECRET_KEY", "DB_PASSWORD"])
def test_disclosed_environment_config_values_are_not_persisted(field):
    value = "synthetic-credential-for-local-test"
    body = f'{field}="{value}"'
    assert value not in capture_text(body)
    assert value not in redact(body)
