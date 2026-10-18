
from app.service import all_of, create, locked, process_job, report
from app.store import Session, now


def seed_job():
    with locked() as s:
        target = create(
            s,
            "target",
            {
                "name": "Scope fixture",
                "kind": "owned",
                "scheme": "http",
                "host": "app.example",
                "port": 80,
                "paths": ["/"],
                "deny_paths": [],
                "verified": True,
                "revoked": False,
                "expires_at": now() + 60,
                "version": 1,
                "used": 0,
                "request_budget": 20,
            },
        )
        endpoint = create(
            s,
            "endpoint",
            {"target_id": target["id"], "method": "GET", "url": "http://app.example/"},
        )
        job = create(
            s,
            "job",
            {
                "target_id": target["id"],
                "endpoint_ids": [endpoint["id"]],
                "account_ids": [],
                "version": 1,
                "used": 0,
                "request_budget": 3,
                "deadline": now() + 60,
                "created_at": now(),
                "status": "running",
            },
        )
        return target, endpoint, job


def test_new_evidence_records_individual_coverage_and_job_logs(monkeypatch):
    _, _, job = seed_job()
    monkeypatch.setattr(
        "app.service.request",
        lambda *a, **k: {
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": "synthetic-only",
            "truncated": False,
        },
    )
    process_job(job["id"])
    with Session() as s:
        ev = all_of(s, "evidence")[0]
        checks = {c["id"]: c["status"] for c in ev["checks"]}
        assert checks["csp-policy"] == "hit"
        assert checks["hsts-policy"] == "not_applicable"
        assert checks["private-key-marker"] == "not_detected"
        assert len(checks) == 6
        assert all_of(s, "check")[0]["status"] == "not_applicable"
        actions = {a["action"] for a in all_of(s, "audit")}
        assert {"job_started", "job_completed", "check_completed"} <= actions
        assert ev["http_exchange"]["response"]["body"] == "synthetic-only"


def test_job_report_excludes_other_task_evidence_and_stays_available_after_delete():
    target, endpoint, job = seed_job()
    with locked() as s:
        other = create(s, "job", dict(job, id=None))
        first = create(
            s,
            "evidence",
            {
                "job_id": job["id"],
                "endpoint_id": endpoint["id"],
                "state": "complete",
                "role": "anonymous",
                "status": 200,
            },
        )
        second = create(
            s,
            "evidence",
            {
                "job_id": other["id"],
                "endpoint_id": endpoint["id"],
                "state": "complete",
                "role": "other-role-unique",
                "status": 200,
            },
        )
        create(
            s,
            "finding",
            {
                "target_id": target["id"],
                "status": "verified",
                "title": "Confirmed synthetic finding",
                "detail": "synthetic detail",
                "impact": "synthetic impact",
                "fix": "synthetic fix",
                "explanation": "synthetic reproduction",
                "evidence_ids": [first["id"], second["id"]],
            },
        )
        from app.target_management import delete_target
    delete_target(target["id"])
    with Session() as s:
        content, _ = report(s, target["id"], "md", job_id=job["id"])
        decoded = content.decode()
        assert first["id"] in decoded
        assert second["id"] not in decoded
        assert "other-role-unique" not in decoded
        assert job["id"] in decoded
