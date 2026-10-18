"""Fixed, budgeted HTTP comparisons; no arbitrary payload or execution interface."""

import hashlib
import json
import re

from .policy import Denied


def validate_rules(body, endpoints):
    from .input_verification import MODES, validate
    validate(body, endpoints)
    if len(set(body.endpoint_ids)) != len(body.endpoint_ids) or len(set(body.account_ids)) != len(body.account_ids):
        raise Denied("接口与账号不可重复绑定")
    rules = body.model_dump().get("verification_rules", {})
    access = {ident for ident in body.endpoint_ids if body.endpoint_test_types.get(ident) == "access_verify"}
    if set(rules) != access:
        raise Denied("访问验证规则必须与访问验证接口一一对应")
    for ident in access:
        rule = rules[ident]
        allowed, denied = rule["allowed_account_id"], rule.get("denied_account_id")
        if not allowed or allowed not in body.account_ids or (denied is not None and denied not in body.account_ids) or allowed == denied:
            raise Denied("验证身份必须为任务绑定的不同专用账号，拒绝身份可为匿名")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", rule["json_field"]) or not re.fullmatch(r"[0-9a-f]{64}", rule["expected_value_sha256"]):
            raise Denied("仅允许顶层合成标记字段及 SHA-256 摘要")
    minimum = 0
    for ident in body.endpoint_ids:
        if endpoints[ident].get("executable") is False:
            raise Denied("该接口不可执行")
        mode = body.endpoint_test_types.get(ident, "both")
        minimum += 3 if mode == "cors_verify" or mode in MODES else 2 if mode == "access_verify" else 1 + (len(body.account_ids) if mode in ("both", "role_compare") else 0)
    if any(mode in ("cors_verify", "access_verify") or mode in MODES for mode in body.endpoint_test_types.values()) and body.request_budget < minimum:
        raise Denied("请求预算不足以完成固定检查组")


def marker_matches(result, rule):
    headers = {k.lower(): v for k, v in result.get("headers", {}).items()}
    if result.get("truncated") or result.get("redirect_blocked") or result.get("status") != 200:
        return None
    if "application/json" not in headers.get("content-type", "").lower() or headers.get("content-encoding", "identity").lower() not in ("", "identity"):
        return None
    try:
        document = json.loads(result["body"])
    except (ValueError, TypeError):
        return None
    value = document.get(rule.get("json_field")) if isinstance(document, dict) else None
    if not isinstance(value, str):
        return False
    return hashlib.sha256(value.encode()).hexdigest() == rule.get("expected_value_sha256")


def evaluate(plugin, responses):
    expected = 3 if plugin == "cors_verify" else 2
    if len(responses) != expected or any(e.get("state") != "complete" or e.get("truncated") or e.get("redirect_blocked") or e.get("http_exchange", {}).get("response", {}).get("truncated") or e.get("http_exchange", {}).get("response", {}).get("headers_truncated") or 300 <= e.get("status", 0) < 400 for e in responses):
        return "inconclusive", "请求未完整结束、被截断或出现跳转，无法完成对照。"
    if plugin == "cors_verify":
        if any(e.get("status") != 200 for e in responses):
            return "inconclusive", "固定对照未全部返回成功响应。"
        if [e.get("probe_label") for e in responses] != ["baseline", "probe_a", "probe_b"]:
            return "inconclusive", "固定探针证据不完整。"
        def reflected(e, origin):
            headers = {k.lower(): v for k, v in e.get("headers", {}).items()}
            return e.get("status") == 200 and headers.get("access-control-allow-origin") == origin and headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        if reflected(responses[1], "https://autominer-a.invalid") and reflected(responses[2], "https://autominer-b.invalid"):
            return "behavior_confirmed", "两个不同固定 Origin 均被精确反射且允许凭证，已确认响应配置行为。"
        return "not_reproduced", "未复现双 Origin 反射且允许凭证的配置行为。"
    allowed, denied = responses
    if allowed.get("probe_label") != "allowed" or denied.get("probe_label") != "denied" or allowed.get("verification_marker_match") is not True:
        return "inconclusive", "允许身份未通过合成标记阳性对照。"
    if denied.get("status") == 200 and denied.get("verification_marker_match") is True:
        return "behavior_confirmed", "预期拒绝身份也返回相同合成标记，已确认与声明权限规则不符的响应行为。"
    if denied.get("status") in (401, 403, 404) or denied.get("verification_marker_match") is False:
        return "not_reproduced", "拒绝身份未获取指定合成标记。"
    return "inconclusive", "拒绝身份响应不足以完成标记对照。"


def run_verification(job_id, endpoint_id, plugin):
    from .service import all_of, audit, create, execute, finding, get, locked, save
    from .store import now

    with locked() as s:
        job = get(s, job_id, "job")
        if plugin not in ("cors_verify", "access_verify") or job.get("endpoint_test_types", {}).get(endpoint_id) != plugin or endpoint_id not in job["endpoint_ids"]:
            raise Denied("验证模板不属于此任务接口")
        if job["status"] != "running":
            raise Denied("任务已停止")
        if any(v["job_id"] == job_id and v["endpoint_id"] == endpoint_id and v["plugin_id"] == plugin for v in all_of(s, "verification")):
            return
        row = create(s, "verification", {
            "job_id": job_id, "target_id": job["target_id"], "endpoint_id": endpoint_id,
            "plugin_id": plugin, "status": "inconclusive", "reason": "固定对照尚未完成；不得自动重放。",
            "evidence_ids": [], "steps": [], "at": now(),
            "criteria": "两次不同 Origin 精确反射并允许凭证" if plugin == "cors_verify" else "允许与拒绝身份均返回声明的顶层合成标记摘要",
            "limitations": "仅验证 HTTP 响应配置；未验证浏览器利用或敏感数据读取。" if plugin == "cors_verify" else "仅验证用户声明权限规则与合成数据；需人工复核业务规则和实际影响。",
        })
        audit(s, "verification_started", job_id, plugin)
    responses = []
    error = None
    try:
        if plugin == "cors_verify":
            for label in ("baseline", "probe_a", "probe_b"):
                responses.append(execute(job_id, endpoint_id, probe_label=label))
        else:
            rule = job["verification_rules"][endpoint_id]
            for account in (rule["allowed_account_id"], rule.get("denied_account_id")):
                responses.append(execute(job_id, endpoint_id, account))
    except Exception as exc:
        error = exc
    status, reason = evaluate(plugin, responses)
    with locked() as s:
        row.update(status=status, reason=reason, evidence_ids=[e["id"] for e in responses],
                   steps=[{"probe_label": e.get("probe_label"), "account_id": e.get("account_id"), "evidence_id": e["id"], "state": e["state"]} for e in responses], completed_at=now())
        save(s, row)
        audit(s, "verification_completed", job_id, plugin + ":" + status)
        if status == "behavior_confirmed":
            finding(s, job, endpoint_id, "受控 CORS 配置行为已复现，待确认影响" if plugin == "cors_verify" else "合成标记权限对照不符，待人工确认", row["evidence_ids"], plugin, reason + row["limitations"])
    if error:
        raise error
