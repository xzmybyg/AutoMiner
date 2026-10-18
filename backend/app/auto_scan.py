"""Persisted, bounded orchestration. Models choose templates, never network tools."""

import os
import hashlib
import json
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from fastapi.responses import Response

from .discovery import candidate
from .policy import Denied, check_url
from .schemas import JobInput, ModelRun
from .service import PASSIVE_CHECKS, active, all_of, audit, create, get, locked, origin, report, save
from .security import capture_text
from .store import Session, now


def authenticated(x_api_key: str = Header(default="")):
    from .main import auth

    return auth(x_api_key)


router = APIRouter(prefix="/api/auto-scans", dependencies=[Depends(authenticated)])
LIVE = ("queued", "running")


def template_costs():
    return dict({"baseline": 1, "injection_errors": 1, "cors_verify": 3},
                **{name: 1 for name in PASSIVE_CHECKS})


class AutoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    include_semantic_context: bool = False
    context: str = Field(default="", max_length=4000)
    target_id: str
    model_id: str
    request_budget: int = Field(default=20, ge=2, le=100)
    discovery_budget: int = Field(default=5, ge=1, le=20)
    duration_seconds: int = Field(default=300, ge=30, le=1800)
    max_cost_usd: float = Field(default=0.1, gt=0, le=5)
    max_rounds: int = Field(default=2, ge=1, le=3)
    allowed_test_types: list[str] = Field(default_factory=lambda: ["baseline"], min_length=1, max_length=20)

    @field_validator("allowed_test_types")
    @classmethod
    def validate_templates(cls, values):
        if any(value not in template_costs() for value in values):
            raise ValueError("自动流程仅允许用户选择的只读白名单模板")
        return list(dict.fromkeys(values))


class AutoProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str = Field(min_length=1, max_length=64)
    test_type: str = Field(min_length=1, max_length=64)
    risk: Literal["low"]
    expected_evidence: str = Field(max_length=1000)
    request_budget: int = Field(ge=1, le=3)


def job_ids(row):
    return list(dict.fromkeys(row.get("job_ids", []) + ([row["job_id"]] if row.get("job_id") else [])))


def refresh_usage(s, row):
    discovery = get(s, row["discovery_id"], "discovery")
    jobs = [get(s, ident, "job") for ident in job_ids(row)]
    row["used"] = discovery["used"] + sum(job["used"] for job in jobs)
    return discovery, jobs


def finish(s, row, target, reason):
    row.update(status="completed", stop_reason=reason, completed_at=now(), phase="completed")
    identifiers = job_ids(row)
    parts = ["# 自动流程报告", f"流程：{row['id']}；停止原因：{reason}",
             f"总请求预留：{row['used']} / {row['request_budget']}；模型费用预算预留：{row.get('model_budget_reserved', 0):.6f} 美元（不代表实际账单）",
             "行为复现与规则命中仍需人工确认影响。"]
    for ident in identifiers:
        content, _ = report(s, target["id"], "md", job_id=ident)
        parts.append(content.decode("utf-8"))
    if not identifiers:
        parts.append("未创建检测任务；没有检测证据，不代表接口已验证或安全。")
    snapshot = create(s, "report", dict(target_id=target["id"], job_id=identifiers[-1] if identifiers else None,
        job_ids=identifiers, auto_scan_id=row["id"], format="md", content="\n\n".join(parts), created_at=now()))
    row["report_id"] = snapshot["id"]
    save(s, row)
    audit(s, "auto_scan_finished", row["id"], reason)


def live(s, row):
    target = get(s, row["target_id"], "target")
    active(target)
    if row["status"] not in LIVE or row["version"] != target["version"]:
        raise Denied("自动流程已停止或授权已变化")
    if row["deadline"] <= now():
        raise Denied("自动流程总时限已到")
    return target


def halt(s, row, status, reason):
    row.update(status=status, error=reason, stop_reason=reason, completed_at=now())
    refresh_usage(s, row)
    for round_row in row.get("rounds", []):
        if round_row.get("status") in ("planning", "testing"):
            round_row.update(status=status, completed_at=now())
    for ident, kind in [(row["discovery_id"], "discovery")] + [(i, "job") for i in job_ids(row)]:
        child = get(s, ident, kind)
        if child["status"] in LIVE:
            child.update(status=status, error=reason)
            save(s, child)
    save(s, row)
    audit(s, "auto_scan_" + status, row["id"], reason)


@router.post("")
def start(body: AutoInput):
    if body.discovery_budget >= body.request_budget:
        raise HTTPException(400, "发现预算必须小于总请求预算，需为检测预留请求")
    if not os.getenv("MODEL_GATEWAY_URL"):
        raise HTTPException(503, "请先配置独立模型出口")
    with locked() as s:
        target = get(s, body.target_id, "target")
        active(target)
        from .models import check_provider

        check_provider(get(s, body.model_id, "model"))
        if body.request_budget > target["request_budget"] - target["used"]:
            raise Denied("超过目标剩余请求预算")
        if any(r["target_id"] == body.target_id and r["status"] in LIVE for r in all_of(s, "auto_scan")):
            raise HTTPException(409, "当前目标已有自动流程")
        data = body.model_dump()
        from .ai_context import semantic_context
        data["context"] = semantic_context(s, target["id"], [], data["context"])["untrusted_business_rules"] if body.include_semantic_context else ""
        row = create(s, "auto_scan", dict(data, version=target["version"],
            status="queued", phase="discovering", created_at=now(),
            deadline=now() + body.duration_seconds, used=0, job_ids=[], rounds=[], executed_pairs=[], model_budget_reserved=0))
        seeds = []
        for value in target["paths"][:10]:
            entry = candidate(target, origin(target) + "/", value, "GET", "授权入口", "入口")
            if not entry["importable"]:
                raise Denied(entry["reason"])
            seeds.append(entry["url"])
        if not seeds:
            raise Denied("授权未设置可发现入口")
        discovery = create(s, "discovery", dict(target_id=target["id"],
            auto_scan_id=row["id"], version=target["version"], seeds=seeds,
            automatic=True, max_depth=2, request_budget=body.discovery_budget,
            status="queued", used=0, created_at=now(), duration_seconds=body.duration_seconds,
            auto_deadline=row["deadline"], requests=[], candidates=[]))
        row["discovery_id"] = discovery["id"]
        save(s, row)
        audit(s, "auto_scan_created", row["id"], "发现、模型安排只读模板、检测；总预算受限")
        return row


@router.get("/{ident}/report")
def download_report(ident: str):
    with Session() as s:
        row = get(s, ident, "auto_scan")
        if not row.get("report_id"):
            raise HTTPException(409, "完整流程报告尚未生成")
        snapshot = get(s, row["report_id"], "report")
        if snapshot.get("auto_scan_id") != ident:
            raise HTTPException(409, "报告关联无效")
        return Response(snapshot["content"], media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="auto-flow-report.md"'})


@router.get("")
def history():
    with Session() as s:
        return sorted(all_of(s, "auto_scan"), key=lambda r: r["created_at"], reverse=True)


@router.post("/{ident}/{action}")
def control(ident: str, action: Literal["pause", "stop"]):
    with locked() as s:
        row = get(s, ident, "auto_scan")
        if row["status"] not in LIVE:
            raise HTTPException(409, "流程已结束；暂停流程不会自动重放，请新建流程")
        halt(s, row, "paused" if action == "pause" else "stopped", "用户暂停或停止自动流程")
    return {"ok": True}


def recover():
    # A crash after a billable request must never cause an automatic paid retry.
    with locked() as s:
        for row in all_of(s, "auto_scan"):
            if row.get("review_status") == "running":
                row.update(review_status="failed", review_error="AI 分析被中断；不会自动重试收费调用")
                save(s, row)
            if row["status"] in LIVE and row["phase"] == "planning":
                halt(s, row, "blocked", "模型规划阶段已中断；不会自动重试收费调用")


def advance():
    """Called by the gateway worker, outside any existing database transaction."""
    with Session() as s:
        identifiers = [r["id"] for r in all_of(s, "auto_scan") if r["status"] in LIVE]
    for ident in identifiers:
        try:
            _advance(ident)
            _review_completed(ident)
        except Exception as exc:
            with locked() as s:
                row = get(s, ident, "auto_scan")
                if row["status"] in LIVE:
                    halt(s, row, "blocked", str(exc) if isinstance(exc, Denied) else "自动流程失败：" + type(exc).__name__)


def _feedback(s, row, children):
    evidence = [e for e in all_of(s, "evidence") if e.get("job_id") in children]
    checks = []
    allowed_status = {"hit", "not_detected", "not_applicable", "inconclusive", "not_run"}
    for evidence_row in evidence:
        for check in evidence_row.get("checks", []):
            ident = str(check.get("id", ""))
            if check.get("status") in allowed_status and ident.replace("-", "").replace("_", "").isalnum():
                checks.append({"endpoint_id": evidence_row["endpoint_id"], "check_id": ident[:100], "status": check["status"]})
    verification = [{"endpoint_id": v["endpoint_id"], "plugin_id": v["plugin_id"], "status": v["status"]}
                    for v in all_of(s, "verification") if v.get("job_id") in children
                    and v.get("status") in {"behavior_confirmed", "not_reproduced", "observed", "inconclusive"}]
    http_status_counts = {}
    for evidence_row in evidence:
        status = evidence_row.get("status")
        if isinstance(status, int) and 100 <= status <= 599:
            http_status_counts[str(status)] = http_status_counts.get(str(status), 0) + 1
    return {"sent_requests": sum(bool(e.get("sent_at")) for e in evidence),
            "completed_requests": sum(e.get("state") == "complete" for e in evidence),
            "http_status_counts": http_status_counts,
            "checks": checks[:100], "verifications": verification[:50]}


def _advance(ident):
    from .main import model_context

    costs = template_costs()
    with locked() as s:
        row = get(s, ident, "auto_scan")
        target = live(s, row)
        discovery, jobs = refresh_usage(s, row)
        rounds = row.setdefault("rounds", [])
        if jobs and not rounds:
            if any(j["status"] in LIVE for j in jobs):
                save(s, row)
                return
            if all(j["status"] == "completed" for j in jobs):
                finish(s, row, target, "历史单轮任务已完成")
            else:
                halt(s, row, "blocked", "历史关联任务未完成")
            return
        if rounds and rounds[-1].get("job_ids") and rounds[-1]["status"] == "testing":
            current_jobs = [get(s, i, "job") for i in rounds[-1]["job_ids"]]
            if any(j["status"] in LIVE for j in current_jobs):
                save(s, row)
                return
            if any(j["status"] != "completed" for j in current_jobs):
                halt(s, row, "blocked", "关联检测任务未完成，停止后续轮次")
                return
            actual = _feedback(s, row, rounds[-1]["job_ids"])
            rounds[-1].update(status="completed", completed_at=now(), actual_summary=actual)
            if not actual["completed_requests"]:
                finish(s, row, target, "未获得新的完整响应证据，停止无进展流程")
                return
        if discovery["status"] in LIVE:
            row["status"] = "running"
            save(s, row)
            return
        if discovery["status"] != "completed":
            raise Denied("接口发现未完成：" + discovery.get("error", discovery["status"]))
        if row["phase"] == "planning":
            save(s, row)
            return
        maximum_rounds = row.get("max_rounds", 1)
        if len(rounds) >= maximum_rounds:
            finish(s, row, target, "已达到允许的轮数上限")
            return
        allowed_types = row.get("allowed_test_types", ["baseline"])
        if any(t not in costs for t in allowed_types):
            raise Denied("自动流程模板配置不合法")
        endpoints = [e for e in all_of(s, "endpoint") if e["target_id"] == target["id"]
                     and e["method"] == "GET" and e.get("executable") and not urlsplit(e["url"]).query][:30]
        if not endpoints:
            raise Denied("未发现可执行 GET 接口；需提供 OpenAPI 或手工导入，未调用模型")
        remaining = min(row["request_budget"] - row["used"], target["request_budget"] - target["used"])
        if remaining <= 0:
            if rounds:
                finish(s, row, target, "总请求预算已用尽")
                return
            raise Denied("发现后剩余请求预算不足，未调用模型")
        executed = {tuple(pair) for pair in row.get("executed_pairs", [])}
        available = []
        for endpoint in endpoints:
            check_url(target, endpoint["url"])
            templates = [t for t in allowed_types if (endpoint["id"], t) not in executed and costs[t] <= remaining]
            if templates:
                available.append({"endpoint_id": endpoint["id"], "test_types": templates})
        if not available:
            finish(s, row, target, "没有预算内的新接口与模板组合，停止重复或无进展流程")
            return
        endpoints = [e for e in endpoints if any(a["endpoint_id"] == e["id"] for a in available)]
        request = ModelRun(model_id=row["model_id"], endpoint_ids=[e["id"] for e in endpoints], max_cost_usd=row["max_cost_usd"])
        _, initial = model_context(s, target["id"], request)
        context = {"endpoints": initial["endpoints"], "allowed_test_types": allowed_types,
                   "available_tests": available, "request_costs": {t: costs[t] for t in allowed_types},
                   "remaining_requests": remaining, "max_requests_per_proposal": 3,
                   "round": len(rounds) + 1,
                   "feedback": [{"round": r["number"], **r["actual_summary"]} for r in rounds if r.get("actual_summary")]}
        if row.get("include_semantic_context"):
            from .ai_context import semantic_context
            context["semantic_context"] = semantic_context(s, target["id"], endpoints, row.get("context", ""), job_ids(row))
        reserved = row.get("model_budget_reserved", 0.0)
        budget = max(0.0, (row["max_cost_usd"] - reserved) / (maximum_rounds - len(rounds) + int(row.get("include_semantic_context", False))))
        if budget <= 0:
            finish(s, row, target, "模型费用预算已用尽")
            return
        row["model_budget_reserved"] = min(row["max_cost_usd"], reserved + budget)
        rounds.append({"number": len(rounds) + 1, "status": "planning", "started_at": now(),
                       "model_budget_reserved": budget, "proposals": [], "job_ids": [],
                       "semantic_context": context.get("semantic_context")})
        row.update(status="running", phase="planning", endpoint_ids=request.endpoint_ids, model_call_started_at=now())
        save(s, row)
        audit(s, "auto_scan_planning", ident, "有界只读规划；按用户选择发送结构化状态及脱敏语义上下文；调用前预留模型费用预算")
    response = httpx.post(os.environ["MODEL_GATEWAY_URL"] + "/internal/model",
        json={"model_id": request.model_id, "context": context, "budget": budget, "planning_mode": "read_only_round"},
        headers={"X-Internal-Token": os.environ["INTERNAL_TOKEN"]}, timeout=45, trust_env=False)
    response.raise_for_status()
    from .ai_context import validate_assessments
    assessments = validate_assessments(response.json().get("assessments", []), context)
    raw = response.json()["proposals"]
    if not isinstance(raw, list) or len(raw) > 30:
        raise Denied("模型未返回有效的有界计划")
    proposals = [AutoProposal.model_validate(p) for p in raw]
    offered = {(a["endpoint_id"], t) for a in available for t in a["test_types"]}
    for proposal in proposals:
        if (proposal.endpoint_id not in request.endpoint_ids or proposal.test_type not in allowed_types
                or proposal.request_budget != costs.get(proposal.test_type)):
            raise Denied("模型计划超出接口、模板或请求成本白名单")
    with locked() as s:
        row = get(s, ident, "auto_scan")
        target = live(s, row)
        if row["phase"] != "planning":
            raise Denied("自动流程阶段已变化")
        discovery, _ = refresh_usage(s, row)
        current = row["rounds"][-1]
        current["assessments"] = assessments
        if not proposals:
            current.update(status="completed", completed_at=now())
            finish(s, row, target, "模型未建议新的允许动作")
            return
        unique = {}
        executed = {tuple(pair) for pair in row.get("executed_pairs", [])}
        for proposal in proposals:
            pair = (proposal.endpoint_id, proposal.test_type)
            if pair in executed:
                continue
            if pair not in offered:
                raise Denied("模型计划未列入本轮可执行组合")
            unique.setdefault(pair, proposal)
        fingerprint = hashlib.sha256(json.dumps(sorted(unique), ensure_ascii=False).encode()).hexdigest()
        current["plan_fingerprint"] = fingerprint
        if not unique or any(r.get("plan_fingerprint") == fingerprint for r in row["rounds"][:-1]):
            current.update(status="completed", completed_at=now())
            finish(s, row, target, "模型重复既有计划，未重复执行请求")
            return
        remaining = min(row["request_budget"] - row["used"], target["request_budget"] - target["used"])
        if sum(costs[t] for _, t in unique) > remaining:
            raise Denied("模型计划超过累计剩余请求预算")
        grouped = {}
        for (endpoint_id, template), proposal in unique.items():
            endpoint = get(s, endpoint_id, "endpoint")
            if endpoint["target_id"] != target["id"] or endpoint["method"] != "GET" or not endpoint.get("executable"):
                raise Denied("模型接口已失效")
            check_url(target, endpoint["url"])
            grouped.setdefault(template, []).append(proposal)
        created_jobs = []
        for template, items in grouped.items():
            mapping = {p.endpoint_id: template for p in items}
            body = JobInput(target_id=target["id"], endpoint_ids=list(mapping), endpoint_test_types=mapping,
                            request_budget=len(mapping) * costs[template], duration_seconds=max(10, int(row["deadline"] - now())))
            job = create(s, "job", dict(body.model_dump(), version=target["version"], status="queued", used=0,
                created_at=now(), deadline=0, auto_deadline=row["deadline"], auto_scan_id=ident,
                round_number=current["number"], test_rationale={p.endpoint_id: capture_text(p.expected_evidence)[:1000] for p in items}))
            created_jobs.append(job["id"])
            audit(s, "job_created", job["id"], "自动流程只读白名单计划")
        current.update(status="testing", job_ids=created_jobs,
                       proposals=[dict(p.model_dump(), expected_evidence=capture_text(p.expected_evidence)[:1000]) for p in unique.values()])
        row["job_ids"] = job_ids(row) + created_jobs
        row["executed_pairs"] = [list(pair) for pair in sorted(executed | set(unique))]
        row.update(phase="testing", job_id=created_jobs[-1], planned_interfaces=len({p.endpoint_id for p in unique.values()}))
        save(s, row)


def _review_completed(ident):
    """One final evidence-only call, pre-reserved and never retried after interruption."""
    from .ai_context import semantic_context, validate_assessments
    with locked() as s:
        row = get(s, ident, "auto_scan")
        if row["status"] != "completed" or not row.get("include_semantic_context") or row.get("review_status"):
            return
        target = get(s, row["target_id"], "target")
        active(target)
        if target["version"] != row["version"] or row["deadline"] <= now():
            return
        budget = row["max_cost_usd"] - row.get("model_budget_reserved", 0)
        if budget <= 0:
            return
        endpoint_ids = list(dict.fromkeys(i for jid in job_ids(row) for i in get(s, jid, "job").get("endpoint_ids", [])))[:30]
        endpoints = [get(s, i, "endpoint") for i in endpoint_ids]
        context = dict(semantic_context=semantic_context(s, target["id"], endpoints, row.get("context", ""), job_ids(row)),
            allowed_test_types=row["allowed_test_types"], available_tests=[], request_costs=template_costs(),
            review_only=True, remaining_requests=0, feedback=_feedback(s, row, job_ids(row)))
        row.update(review_status="running", model_budget_reserved=row["max_cost_usd"])
        save(s, row)
        audit(s, "auto_scan_evidence_review", ident, "最终证据分析；不执行额外目标请求")
        model_id = row["model_id"]
    try:
        response = httpx.post(os.environ["MODEL_GATEWAY_URL"] + "/internal/model",
            json=dict(model_id=model_id, context=context, budget=budget, planning_mode="read_only_round"),
            headers={"X-Internal-Token": os.environ["INTERNAL_TOKEN"]}, timeout=45, trust_env=False)
        response.raise_for_status()
        result = response.json()
        if result.get("proposals") != []:
            raise Denied("最终分析不能安排新的请求")
        assessments = validate_assessments(result.get("assessments", []), context)
        with locked() as s:
            row = get(s, ident, "auto_scan")
            target = get(s, row["target_id"], "target")
            active(target)
            if target["version"] != row["version"] or row["deadline"] <= now():
                raise Denied("授权已变更或流程已超时")
            row.update(review_status="completed", assessments=assessments)
            save(s, row)
            snapshot = get(s, row["report_id"], "report")
            snapshot["content"] += "\n\n## AI 证据分析（待人工确认）\n" + json.dumps(assessments, ensure_ascii=False, indent=2)
            save(s, snapshot)
    except Exception:
        with locked() as s:
            row = get(s, ident, "auto_scan")
            row.update(review_status="failed", review_error="AI 最终分析未完成，检测证据保留；不会自动重试收费调用")
            save(s, row)
