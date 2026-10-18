import pytest

from app.access_control_checks import compare_responses


def response(ident, account=None, status=200, digest="same", state="complete"):
    return {"id": ident, "account_id": account, "role": "reader" if account else "anonymous",
            "state": state, "status": status, "body_sha256": digest}


def test_same_role_distinct_accounts_compare_even_when_anonymous_differs():
    rows = [response("anon", status=403), response("a", "account-a"), response("b", "account-b")]
    check, evidence = compare_responses(rows, True)
    assert check["status"] == "hit"
    assert evidence == ["a", "b"]
    assert "权限矩阵" in check["detail"]


@pytest.mark.parametrize("rows", [
    [response("a", "same-account"), response("b", "same-account")],
    [response("a", "one", status=403), response("b", "two", status=403)],
    [response("a", "one", digest="first"), response("b", "two", digest="second")],
    [response("a", "one", digest=""), response("b", "two", digest="")],
])
def test_non_comparable_or_distinct_responses_are_not_findings(rows):
    check, evidence = compare_responses(rows, True)
    assert check["status"] == "not_detected"
    assert evidence == []


def test_missing_accounts_and_incomplete_evidence_are_explicit():
    check, evidence = compare_responses([response("anon")], False)
    assert check["status"] == "not_applicable" and evidence == []
    check, evidence = compare_responses([response("anon"), response("a", "one", state="failed")], True)
    assert check["status"] == "inconclusive" and evidence == []


def test_job_compares_same_role_accounts_and_only_links_matching_evidence(monkeypatch):
    from app.service import all_of, locked, process_job
    from test_app import make_job, post, setup_target

    target, endpoint = setup_target()
    accounts = [post(f"/targets/{target['id']}/accounts", {
        "name": name, "role": "reader", "headers": {"X-Test-Account": name},
        "synthetic_data_only": True,
    }).json() for name in ("synthetic-a", "synthetic-b")]
    job = make_job(target, endpoint, account_ids=[a["id"] for a in accounts],
                   endpoint_test_types={endpoint["id"]: "role_compare"})
    sent = []
    def transport(target, url, headers, before_send):
        before_send()
        sent.append(url)
        return {"status": 200 if headers else 403, "headers": {"Content-Type": "text/plain"},
                "body": "synthetic shared resource" if headers else "denied", "truncated": False}
    monkeypatch.setattr("app.service.request", transport)
    process_job(job["id"])
    assert sent == [endpoint["url"]] * 3
    with locked() as s:
        evidence = all_of(s, "evidence")
        findings = all_of(s, "finding")
        assert len(findings) == 1 and findings[0]["status"] == "pending"
        assert findings[0]["evidence_ids"] == [e["id"] for e in evidence if e["account_id"]]
        assert {e["account_id"] for e in evidence if e["account_id"]} == {a["id"] for a in accounts}
