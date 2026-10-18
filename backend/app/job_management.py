"""Read-only task history with strictly task-scoped execution evidence."""

from fastapi import APIRouter, Depends, Header

from .security import redact
from .service import all_of, get
from .store import Session
from .scan_runs import history, scope


def authenticate(x_api_key: str = Header(default="")):
    from .main import auth

    return auth(x_api_key)


router = APIRouter(dependencies=[Depends(authenticate)])


def summary(job, targets, audits):
    created = job.get("created_at") or next(
        (
            a.get("at")
            for a in audits
            if a.get("subject") == job["id"] and a.get("action") == "job_created"
        ),
        None,
    )
    return dict(
        job,
        created_at=created,
        target_name=targets.get(job["target_id"], {}).get("name", "历史目标"),
        interface_count=len(job.get("endpoint_ids", [])),
    )


@router.get("/api/jobs")
def list_jobs():
    with Session() as s:
        targets = {t["id"]: t for t in all_of(s, "target")}
        audits = all_of(s, "audit")
        return sorted(
            [summary(j, targets, audits) for j in history(s)],
            key=lambda j: j.get("created_at") or 0,
            reverse=True,
        )


@router.get("/api/jobs/{job_id}")
def job_detail(job_id: str):
    with Session() as s:
        job, member_ids, discovery_ids = scope(s, job_id)
        targets = {t["id"]: t for t in all_of(s, "target")}
        audits = all_of(s, "audit")
        evidence = [e for e in all_of(s, "evidence") if e.get("job_id") in member_ids and e.get("target_id", job['target_id']) == job['target_id']]
        evidence_ids = {e["id"] for e in evidence}
        # Only the bounded redacted exchange is exposed, never raw credentials.
        fields = (
            "id",
            "endpoint_id",
            "url",
            "method",
            "role",
            "account_id",
            "probe_label",
            "verification_marker_match",
            "at",
            "sent_at",
            "completed_at",
            "state",
            "status",
            "error",
            "test_mode",
            "checks",
            "signals",
            "redirect_blocked",
            "truncated",
            "body_bytes",
            "http_exchange",
        )
        safe_evidence = [
            {
                k: redact(v) if isinstance(v, str) and k == "url" else v
                for k, v in e.items()
                if k in fields
            }
            for e in evidence
        ]
        endpoints = {e["id"]: e for e in all_of(s, "endpoint")}
        rows = []
        for ident in job.get("endpoint_ids", []):
            endpoint = endpoints.get(ident, {})
            requests = sorted(
                [e for e in safe_evidence if e.get("endpoint_id") == ident],
                key=lambda e: e.get("at", 0),
            )
            rows.append(
                {
                    "id": ident,
                    "method": endpoint.get("method", "GET"),
                    "url": redact(endpoint.get("url", "历史接口已不可用")),
                    "test_mode": job.get("endpoint_test_types", {}).get(ident, "both"),
                    "test_modes": job.get('endpoint_test_modes', {}).get(ident, []),
                    "requests": requests,
                    "rationale": redact(job.get("test_rationale", {}).get(ident, "")),
                    "state": "recorded" if requests else "not_requested",
                }
            )
        findings = [
            dict(
                f,
                evidence_ids=[
                    i for i in f.get("evidence_ids", []) if i in evidence_ids
                ],
            )
            for f in all_of(s, "finding")
            if evidence_ids.intersection(f.get("evidence_ids", []))
        ]
        logs = [
            {
                "id": a["id"],
                "at": a.get("at"),
                "action": a.get("action"),
                "subject": a.get("subject"),
                "job_id": job_id,
                "detail": redact(a.get("detail", "")),
            }
            for a in audits
            if a.get("job_id") in member_ids
            or a.get("subject") in set(member_ids + discovery_ids + [job_id]) or a.get("subject") in evidence_ids
        ]
        verifications = [v for v in all_of(s, "verification") if v.get("job_id") in member_ids and v.get('target_id', job['target_id']) == job['target_id']]
        coverage = {
            "planned_endpoints": len(rows),
            "requested_endpoints": sum(any(e.get("sent_at") for e in r["requests"]) for r in rows),
            "endpoints_with_evidence": sum(bool(r["requests"]) for r in rows),
            "not_requested_endpoints": sum(not r["requests"] for r in rows),
            "sent_requests": sum(bool(e.get("sent_at")) for e in evidence),
            "completed_requests": sum(e.get("state") == "complete" for e in evidence),
            "failed_requests": sum(e.get("state") in ("failed", "interrupted") for e in evidence),
            "recorded_checks": sum(len(e.get("checks", [])) for e in evidence),
            "verification_count": len(verifications),
        }
        return {
            "job": summary(job, targets, audits),
            "steps": [dict(id=j['id'], status=j['status'], used=j.get('used', 0),
                test_types=sorted(set(j.get('endpoint_test_types', {}).values())))
                for j in all_of(s, 'job') if j['id'] in member_ids] if job.get('is_run') else [],
            "endpoints": rows,
            "evidence": safe_evidence,
            "verifications": sorted(verifications, key=lambda v: v.get("at") or 0),
            "coverage": coverage,
            "findings": findings,
            "job_checks": [c for c in all_of(s, "check") if c.get("job_id") in member_ids],
            "logs": sorted(logs, key=lambda a: a.get("at") or 0),
            "coverage_note": "仅展示已持久化的检查结果；历史证据没有检查明细时，不推断已检查或已通过。",
        }
