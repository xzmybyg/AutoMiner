import json

from app.job_management import job_detail
from app.security import HTTP_CAPTURE_LIMIT, http_exchange
from app.service import all_of, execute, locked, report
from app.store import Session
from test_reporting_and_checks import seed_job


def response(body="synthetic retained text", content_type="text/plain", **extra):
    return dict(
        status=200,
        headers={"Content-Type": content_type},
        body=body,
        truncated=False,
        request_headers={"Host": "app.example:80"},
        **extra,
    )


def test_retains_redacted_exchange_in_job_detail_and_report(monkeypatch):
    target, endpoint, job = seed_job()
    result = response()
    result["headers"]["X-Trace"] = "trace-123"
    result["headers"]["Set-Cookie"] = "sid=secret-cookie"
    result["request_headers"]["Authorization"] = "Bearer secret-token"
    monkeypatch.setattr("app.service.request", lambda *a, **k: result)
    ev = execute(job["id"], endpoint["id"])
    exchange = ev["http_exchange"]
    assert exchange["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert exchange["request"]["body_state"] == "absent"
    assert exchange["response"]["headers"]["X-Trace"] == "trace-123"
    assert exchange["response"]["body"] == "synthetic retained text"
    assert "secret-cookie" not in json.dumps(ev)
    assert job_detail(job["id"])["evidence"][0]["http_exchange"] == exchange
    with Session() as s:
        document, _ = report(s, target["id"], "zip", job["id"])
        assert len(document) > 100
        assert all_of(s, "evidence")[0]["http_exchange"] == exchange


def test_json_nested_secrets_and_pii_are_redacted():
    result = response(
        json.dumps(
            {
                "result": {
                    "password": "hunter2",
                    "api_key": "key123",
                    "email": "person@example.org",
                    "profile": {"name": "Alice"},
                },
                "safe": "keep",
                "echo": "Bearer account-token",
            }
        ),
        "application/json",
    )
    captured = http_exchange("http://app.example/", result, ["Bearer account-token"])
    body = json.loads(captured["response"]["body"])
    assert body["safe"] == "keep"
    for secret in ("hunter2", "key123", "person@example.org", "Alice", "account-token"):
        assert secret not in json.dumps(captured)


def test_text_credentials_pii_and_multiline_private_key_are_redacted():
    source = (
        "password=not-for-storage\nadmin@example.org 13812345678\n"
        "-----BEGIN RSA PRIVATE KEY-----\nprivate-material\n"
        "-----END RSA PRIVATE KEY-----\nkeep"
    )
    capture = http_exchange("http://app.example/", response(source))
    serialized = json.dumps(capture)
    for secret in (
        "not-for-storage",
        "admin@example.org",
        "13812345678",
        "private-material",
    ):
        assert secret not in serialized
    assert "keep" in capture["response"]["body"]


def test_capture_bounds_headers_and_text_and_preserves_transport_truncation():
    result = response("界" * 70000, body_bytes=65536)
    result["headers"].update({f"X-{i}": "a" * 4000 for i in range(500)})
    capture = http_exchange("http://app.example/", result)
    headers = capture["request"]["headers"] | capture["response"]["headers"]
    total = sum(len(k.encode()) + len(v.encode()) for k, v in headers.items())
    total += len(capture["response"]["body"].encode()) + len(
        capture["request"]["url"].encode()
    )
    assert total <= HTTP_CAPTURE_LIMIT
    assert capture["response"]["headers_truncated"]
    assert capture["response"]["truncated"]
    assert capture["response"]["body_bytes"] == 65536


def test_binary_and_encoded_responses_are_not_misrepresented_as_text():
    capture = http_exchange(
        "http://app.example/", response("binary-secret", "image/png")
    )
    assert capture["response"]["body_state"] == "omitted_non_text"
    assert capture["response"]["body"] == ""
    result = response("compressed-secret")
    result["headers"]["Content-Encoding"] = "gzip"
    capture = http_exchange("http://app.example/", result)
    assert capture["response"]["body_state"] == "omitted_encoded"
    assert capture["response"]["body"] == ""


def test_failure_and_legacy_evidence_do_not_fabricate_capture(monkeypatch):
    _, endpoint, job = seed_job()

    def fail(*a, **k):
        raise TimeoutError("secret error content")

    monkeypatch.setattr("app.service.request", fail)
    ev = execute(job["id"], endpoint["id"])
    assert ev["state"] == "failed"
    assert ev["http_exchange"]["request"]["body_state"] == "not_captured"
    assert ev["http_exchange"]["response"]["body_state"] == "not_captured"
    assert "secret error content" not in json.dumps(ev)
    from app.service import create

    with locked() as s:
        old = create(
            s,
            "evidence",
            {"job_id": job["id"], "endpoint_id": endpoint["id"], "state": "complete"},
        )
    historical = next(
        e for e in job_detail(job["id"])["evidence"] if e["id"] == old["id"]
    )
    assert "http_exchange" not in historical


def test_transport_records_headers_it_actually_sends(monkeypatch):
    from app.policy import request

    sent = {}

    class Response:
        status = 200

        def read1(self, count):
            return b""

        def getheaders(self):
            return [("Content-Type", "text/plain")]

        def getheader(self, key):
            return None

    class Connection:
        sock = None

        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, headers):
            sent.update(method=method, path=path, headers=headers)

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr("app.policy.resolve", lambda t: ["93.184.216.34"])
    monkeypatch.setattr("app.policy.http.client.HTTPConnection", Connection)
    result = request(
        {
            "scheme": "http",
            "host": "app.example",
            "port": 80,
            "paths": ["/"],
            "deny_paths": [],
            "kind": "owned",
        },
        "http://app.example/",
        {"Cookie": "sid=account-cookie"},
    )
    assert result["request_headers"] == sent["headers"]
    assert result["request_headers"]["Accept-Encoding"] == "identity"
    capture = http_exchange("http://app.example/", result, ["sid=account-cookie"])
    assert capture["request"]["headers"]["Cookie"] == "[REDACTED]"
    assert capture["request"]["body_state"] == "absent"


def test_deep_and_truncated_json_never_falls_back_to_unredacted_pii():
    deep = "[" * 2000 + '"private-person@example.org"' + "]" * 2000
    captured = http_exchange("http://app.example/", response(deep, "application/json"))
    assert captured["response"]["body"] == "[OMITTED: deeply nested JSON]"
    broken = (
        '{"profile":{"name":"Private Person","address":"Private Street",'
        '"password":"very-private'
    )
    captured = http_exchange(
        "http://app.example/", response(broken, "application/json")
    )
    for secret in ("Private Person", "Private Street", "very-private"):
        assert secret not in json.dumps(captured)


def test_account_credentials_are_redacted_even_when_echoed_under_innocent_keys(
    monkeypatch,
):
    from app.security import encrypt
    from app.service import create, save

    target, endpoint, job = seed_job()
    credentials = {
        "Authorization": "Bearer echo-token",
        "Cookie": "sid=echo-cookie; csrf=echo-csrf",
    }
    with locked() as s:
        account = create(
            s,
            "account",
            {
                "target_id": target["id"],
                "role": "test-role",
                "encrypted_headers": encrypt(credentials),
            },
        )
        job["account_ids"] = [account["id"]]
        save(s, job)
    result = response(
        '{"ref":["echo-token","echo-cookie","echo-csrf"]}', "application/json"
    )
    result["request_headers"] = credentials
    monkeypatch.setattr("app.service.request", lambda *a, **k: result)
    ev = execute(job["id"], endpoint["id"], account["id"])
    for secret in ("echo-token", "echo-cookie", "echo-csrf"):
        assert secret not in json.dumps(ev)
