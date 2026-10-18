import hashlib
import html
import io
import json
import re
import zipfile
from contextlib import contextmanager
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import update

from .policy import Denied, check_url, request
from .injection_checks import inspect_errors
from .xss_checks import inspect_response as inspect_xss
from .csrf_checks import inspect_response as inspect_csrf
from .ssrf_checks import inspect_response as inspect_ssrf
from .xxe_checks import inspect_response as inspect_xxe
from .file_checks import inspect_response as inspect_file
from .deserialization_checks import inspect_response as inspect_deserialization
from .auth_session_checks import inspect_response as inspect_auth_session
from .access_control_checks import compare_responses
from .disclosure_checks import inspect_response as inspect_disclosure
from .configuration_checks import inspect_response as inspect_configuration
from .crypto_checks import inspect_response as inspect_crypto
from .supply_chain_checks import inspect_response as inspect_supply_chain
from .business_logic_checks import inspect_response as inspect_business_logic
from .other_web_checks import inspect_response as inspect_other_web
from .race_condition_checks import inspect_response as inspect_race_condition
from .memory_safety_checks import inspect_response as inspect_memory_safety
from .dos_checks import inspect_response as inspect_dos
from .security import decrypt, http_exchange, redact
from .store import Mutex, Record, Session, now

PASSIVE_CHECKS = {
    "xss_passive": inspect_xss,
    "csrf_passive": inspect_csrf,
    "ssrf_passive": inspect_ssrf,
    "xxe_passive": inspect_xxe,
    "file_passive": inspect_file,
    "deserialization_passive": inspect_deserialization,
    "auth_session_passive": inspect_auth_session,
    "disclosure_passive": inspect_disclosure,
    "configuration_passive": inspect_configuration,
    "crypto_passive": inspect_crypto,
    "supply_chain_passive": inspect_supply_chain,
    "business_logic_review": inspect_business_logic,
    "other_web_passive": inspect_other_web,
    "race_condition_review": inspect_race_condition,
    "memory_safety_passive": inspect_memory_safety,
    "dos_passive": inspect_dos,
}


def create(s, kind, data):
    data = dict(data, id=uuid4().hex)
    s.add(
        Record(id=data["id"], kind=kind, payload=json.dumps(data, ensure_ascii=False))
    )
    s.flush()
    return data


def get(s, ident, kind=None):
    row = s.get(Record, ident)
    if not row or (kind and row.kind != kind):
        raise HTTPException(404, "记录不存在")
    return json.loads(row.payload)


def save(s, data):
    s.get(Record, data["id"]).payload = json.dumps(data, ensure_ascii=False)


def all_of(s, kind):
    return [json.loads(r.payload) for r in s.query(Record).filter_by(kind=kind).all()]


@contextmanager
def locked():
    with Session.begin() as s:
        s.execute(
            update(Mutex).where(Mutex.id == 1).values(revision=Mutex.revision + 1)
        )
        yield s


def audit(s, action, subject, detail=""):
    row = s.get(Record, subject)
    related = json.loads(row.payload) if row else {}
    job_id = subject if row and row.kind == "job" else related.get("job_id")
    create(
        s,
        "audit",
        {"at": now(), "action": action, "subject": subject, "detail": detail,
         "job_id": job_id},
    )


def active(target):
    if (
        target["kind"] == "src"
        or not target.get("verified")
        or target.get("revoked")
        or target.get("deleted")
        or target["expires_at"] <= now()
    ):
        raise Denied("目标未验证、已撤销、已过期，或仅允许整理 SRC 报告")


def origin(target):
    host = "[" + target["host"] + "]" if ":" in target["host"] else target["host"]
    return f"{target['scheme']}://{host}:{target['port']}"


def public_target(target):
    # Identity stays stable through edits; same-address registrations remain distinct.
    return dict(target, hash=hashlib.sha256(target["id"].encode()).hexdigest())


def reserve_request(job_id, endpoint_id, account_id=None):
    with locked() as s:
        job = get(s, job_id, "job")
        target = get(s, job["target_id"], "target")
        active(target)
        if job["version"] != target["version"] or job["status"] != "running":
            raise Denied("任务或授权版本已失效")
        if (
            job["deadline"] <= now()
            or job["used"] >= job["request_budget"]
            or target["used"] >= target["request_budget"]
        ):
            raise Denied("任务时限或请求预算已用尽")
        endpoint = get(s, endpoint_id, "endpoint")
        if (
            endpoint["target_id"] != target["id"]
            or endpoint_id not in job["endpoint_ids"]
            or endpoint["method"] != "GET"
            or endpoint.get("executable") is False
        ):
            raise Denied("接口不属于任务或需要写入；首版执行器只开放 GET")
        check_url(target, endpoint["url"])
        headers, role = {}, "anonymous"
        if account_id:
            if account_id not in job["account_ids"]:
                raise Denied("账号未绑定任务")
            account = get(s, account_id, "account")
            if account["target_id"] != target["id"]:
                raise Denied("账号不属于目标")
            headers, role = decrypt(account["encrypted_headers"]), account["role"]
        job["used"] += 1
        target["used"] += 1
        save(s, job)
        save(s, target)
        ev = create(
            s,
            "evidence",
            {
                "job_id": job_id,
                "target_id": target["id"],
                "version": target["version"],
                "endpoint_id": endpoint_id,
                "role": role,
                "account_id": account_id,
                "at": now(),
                "state": "reserved",
                "url": redact(endpoint["url"]),
                "method": "GET",
                "test_mode": job.get("endpoint_test_types", {}).get(
                    endpoint_id, "both"
                ),
            },
        )
        audit(s, "request_reserved", ev["id"])
        return target, endpoint, headers, ev


def execute(job_id, endpoint_id, account_id=None, *, probe_label=None):
    if probe_label is not None:
        with Session() as s:
            mode = get(s, job_id, "job").get("endpoint_test_types", {}).get(endpoint_id)
        if mode != "cors_verify" or account_id is not None or probe_label not in ("baseline", "probe_a", "probe_b"):
            raise Denied("固定 Origin 探针仅用于匿名 CORS 验证")
    target, endpoint, headers, ev = reserve_request(job_id, endpoint_id, account_id)
    if probe_label is not None:
        ev["probe_label"] = probe_label
    try:

        def authorize_dispatch():
            # DNS resolution can be slow. Re-check live authorization after it,
            # immediately before granting this already-reserved request dispatch.
            with locked() as s:
                current = get(s, target["id"], "target")
                job = get(s, job_id, "job")
                active(current)
                if (
                    current["version"] != job["version"]
                    or job["status"] != "running"
                    or job["deadline"] <= now()
                ):
                    raise Denied("发送前授权或任务已失效")
                ev.update(state="in_flight", sent_at=now())
                save(s, ev)
                audit(s, "request_dispatched", ev["id"])

        kwargs = {"probe_label": probe_label} if probe_label is not None else {}
        result = request(target, endpoint["url"], headers, before_send=authorize_dispatch, **kwargs)
        if ev["test_mode"] == "access_verify":
            from .active_verification import marker_matches
            with Session() as s:
                rule = get(s, job_id, "job").get("verification_rules", {}).get(endpoint_id, {})
            ev["verification_marker_match"] = marker_matches(result, rule)
            ev["probe_label"] = "allowed" if account_id == rule.get("allowed_account_id") else "denied"
        discovered = []

        class Links(HTMLParser):
            def handle_starttag(self, tag, attrs):
                if tag != "a" or len(discovered) >= 20:
                    return
                href = dict(attrs).get("href")
                if not href:
                    return
                candidate = urljoin(endpoint["url"], href)
                try:
                    check_url(target, candidate)
                    if not urlsplit(candidate).query and candidate not in discovered:
                        discovered.append(candidate)
                except (Denied, ValueError):
                    pass

        if any(
            k.lower() == "content-type" and "text/html" in v.lower()
            for k, v in result["headers"].items()
        ):
            Links().feed(result["body"])
        private = list(headers.values())
        if ev["test_mode"] == "access_verify":
            try:
                marker = json.loads(result["body"]).get(rule.get("json_field"))
                if isinstance(marker, str) and marker:
                    private.append(marker)
            except (ValueError, TypeError, AttributeError):
                pass
        signals = []
        lower_headers = {k.lower(): v for k, v in result["headers"].items()}
        if (
            "text/html" in lower_headers.get("content-type", "").lower()
            and "content-security-policy" not in lower_headers
        ):
            signals.append({"root": "csp-policy", "title": "HTML 响应缺少内容安全策略"})
        if (
            target["scheme"] == "https"
            and "strict-transport-security" not in lower_headers
        ):
            signals.append({"root": "hsts-policy", "title": "HTTPS 响应缺少 HSTS 策略"})
        for pattern, root, title in [
            (
                r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                "private-key-marker",
                "响应出现私钥格式标记",
            ),
            (
                r"Traceback \(most recent call last\):|at [\w.$]+\([\w.]+\.java:\d+\)",
                "debug-trace",
                "响应出现调试堆栈标记",
            ),
        ]:
            if re.search(pattern, result["body"]):
                signals.append({"root": root, "title": title})
        injection_checks, injection_signals = inspect_errors(result["body"])
        if ev["test_mode"] == "injection_errors":
            signals = injection_signals
        elif ev["test_mode"] in PASSIVE_CHECKS:
            passive_checks, signals = PASSIVE_CHECKS[ev["test_mode"]](
                result["body"], result["headers"]
            )
        else:
            signals.extend(
                {"root": "database-error", "title": "响应出现数据库错误标记"}
                for signal in injection_signals if signal["root"] == "database-error"
            )
        safe_headers = {
            k: v
            for k, v in result["headers"].items()
            if k.lower()
            in (
                "content-type",
                "content-security-policy",
                "x-content-type-options",
                "strict-transport-security",
                "access-control-allow-origin",
                "access-control-allow-credentials",
            )
        }
        # Persist only the bounded, redacted exchange; never the raw response.
        checks = []
        if ev["test_mode"] in ("baseline", "both"):
            hit_roots = {signal["root"] for signal in signals}
            if (
                result["status"] == 200
                and "x-content-type-options" not in lower_headers
            ):
                hit_roots.add("mime-policy")
            for ident, name, applicable in [
                ("mime-policy", "MIME 嗅探限制响应头", result["status"] == 200),
                (
                    "csp-policy",
                    "HTML 内容安全策略 CSP",
                    "text/html" in lower_headers.get("content-type", "").lower(),
                ),
                ("hsts-policy", "HTTPS 严格传输策略 HSTS", target["scheme"] == "https"),
                ("private-key-marker", "私钥格式标记", True),
                ("debug-trace", "调试堆栈标记", True),
                ("database-error", "数据库错误标记", True),
            ]:
                status = (
                    "not_applicable"
                    if not applicable
                    else ("hit" if ident in hit_roots else "not_detected")
                )
                checks.append(
                    {
                        "id": ident,
                        "name": name,
                        "status": status,
                        "detail": "仅检查本次响应中已读取的内容；未命中不代表不存在漏洞。"
                        if applicable
                        else "本次响应协议、类型或状态不适用此检查。",
                    }
                )
        elif ev["test_mode"] == "injection_errors":
            checks = injection_checks
        elif ev["test_mode"] in PASSIVE_CHECKS:
            checks = passive_checks
        elif ev["test_mode"] in ("cors_verify", "access_verify"):
            signals = []
            checks = [{"id": ev["test_mode"], "name": "固定 HTTP 对照取证", "status": "observed", "detail": "单条响应不作漏洞判断，参见任务的聚合验证结论。"}]
        else:
            checks.append(
                {
                    "id": "baseline",
                    "name": "响应配置与敏感标记检查",
                    "status": "not_run",
                    "detail": "本任务仅选择身份响应对比。",
                }
            )
        ev.update(
            state="complete",
            status=result["status"],
            headers=json.loads(redact(json.dumps(safe_headers), private)),
            body_sha256=hashlib.sha256(result["body"].encode()).hexdigest(),
            body_bytes=result.get("body_bytes", len(result["body"].encode())),
            truncated=result["truncated"],
            redirect_blocked=result.get("redirect_blocked", False),
            discovered_urls=[redact(u, private) for u in discovered],
            signals=signals,
            checks=checks,
            completed_at=now(),
            http_exchange=http_exchange(endpoint["url"], result, private),
        )
    except Exception as exc:
        ev.update(
            state="failed",
            error=type(exc).__name__,
            completed_at=now(),
            http_exchange=http_exchange(
                endpoint["url"], secrets=list(headers.values())
            ),
            checks=[
                {
                    "id": "baseline",
                    "name": "响应检查",
                    "status": "not_run",
                    "detail": "请求未完成，未获得可检查的完整响应。",
                }
            ],
        )
    with locked() as s:
        save(s, ev)
        current = get(s, job_id, "job")
        if account_id and ev.get("status") == 401 and not current.get("identity_check"):
            account = get(s, account_id, "account")
            current = get(s, job_id, "job")
            if current["status"] == "running" and account.get("last_validation", {}).get("status") == "valid" and decrypt(account["encrypted_headers"]) == headers:
                account["last_validation"] = dict(status="invalid", reason="检查接口拒绝会话（401），请重新验证登录", at=now(), job_id=job_id, version=current["version"], evidence_ids=[ev["id"]])
                save(s, account)
                current.update(status="blocked", error="账号会话被拒绝，请更新凭证并验证后新建检查")
                save(s, current)
        audit(s, "request_finished", ev["id"], ev["state"])
        audit(
            s, "check_completed", ev["id"], json.dumps(ev["checks"], ensure_ascii=False)
        )
    return ev


def finding(s, job, endpoint, title, evidence, root, detail):
    fingerprint = hashlib.sha256(
        f"{job['target_id']}:{endpoint}:{root}".encode()
    ).hexdigest()
    existing = next(
        (
            f
            for f in all_of(s, "finding")
            if f["fingerprint"] == fingerprint and f["status"] != "false_positive"
        ),
        None,
    )
    if existing:
        existing["evidence_ids"] = list(
            dict.fromkeys(existing["evidence_ids"] + evidence)
        )
        existing["status"] = "pending"
        save(s, existing)
        return
    create(
        s,
        "finding",
        {
            "target_id": job["target_id"],
            "job_id": job["id"],
            "endpoint_id": endpoint,
            "title": title,
            "status": "pending",
            "evidence_ids": evidence,
            "fingerprint": fingerprint,
            "detail": detail,
            "impact": "需要结合业务权限与实际部署确认影响",
            "fix": "按服务端权限矩阵校验请求，并配置适当的响应安全策略",
            "explanation": "",
        },
    )


def process_job(job_id):
    with locked() as s:
        job = get(s, job_id, "job")
        if job["status"] != "running":
            return
        job["started_at"] = job.get("started_at", now())
        save(s, job)
        audit(s, "job_started", job_id)
    try:
        for endpoint in job["endpoint_ids"]:
            mode = job.get("endpoint_test_types", {}).get(endpoint, "both")
            if mode in ("cors_verify", "access_verify"):
                from .active_verification import run_verification
                run_verification(job_id, endpoint, mode)
                continue
            accounts = job["account_ids"] if mode in ("role_compare", "both") else []
            responses = [
                execute(job_id, endpoint, account) for account in [None] + accounts
            ]
            with locked() as s:
                for ev in responses:
                    if (mode in ("baseline", "both", "injection_errors") or mode in PASSIVE_CHECKS) and ev["state"] == "complete":
                        for signal in ev.get("signals", []):
                            finding(
                                s,
                                job,
                                endpoint,
                                signal["title"],
                                [ev["id"]],
                                signal["root"],
                                "被动响应规则命中，保留标记、摘要和限量脱敏 HTTP 证据。"
                                "标记可能来自示例内容，需在授权环境人工复现与确认影响。",
                            )
                    if (
                        mode in ("baseline", "both")
                        and ev["state"] == "complete"
                        and ev["status"] == 200
                        and "x-content-type-options"
                        not in {k.lower() for k in ev["headers"]}
                    ):
                        finding(
                            s,
                            job,
                            endpoint,
                            "响应缺少 MIME 嗅探限制，请确认影响",
                            [ev["id"]],
                            "mime-policy",
                            "检查 X-Content-Type-Options；此配置线索不代表可利用漏洞。",
                        )
                if mode in ("role_compare", "both"):
                    comparison, matching_ids = compare_responses(responses, bool(accounts))
                    comparison_status = comparison["status"]
                    create(
                        s,
                        "check",
                        {
                            "job_id": job_id,
                            "endpoint_id": endpoint,
                            "evidence_ids": [e["id"] for e in responses],
                            **comparison,
                            "at": now(),
                        },
                    )
                    audit(
                        s,
                        "check_completed",
                        job_id,
                        "身份响应摘要对比：" + comparison_status,
                    )
                if mode in ("role_compare", "both") and matching_ids:
                    finding(
                        s,
                        job,
                        endpoint,
                        "不同身份返回相同内容，待确认权限边界",
                        matching_ids,
                        "role-comparison",
                        "匿名或专用账号间存在成功响应摘要相同的身份对；公开资源也可能如此，需要资源归属、权限矩阵及人工复现。",
                    )
        with locked() as s:
            current = get(s, job_id, "job")
            if current["status"] == "running":
                current["status"] = "completed"
                current["completed_at"] = now()
                save(s, current)
                from .account_management import finalize
                finalize(s, current)
                audit(s, "job_completed", job_id)
    except Exception as exc:
        with locked() as s:
            current = get(s, job_id, "job")
            if current["status"] == "running":
                current.update(
                    status="blocked",
                    error=str(exc) if isinstance(exc, Denied) else type(exc).__name__,
                )
                save(s, current)
                audit(s, "job_blocked", job_id, current["error"])


def report(s, target_id, fmt, job_id=None):
    target = get(s, target_id, "target")
    from .scan_runs import scope
    job, member_ids, _ = scope(s, job_id, target_id) if job_id else (None, [], [])
    job_evidence = (
        [e for e in all_of(s, "evidence") if e.get("job_id") in member_ids and e.get('target_id', target_id) == target_id]
        if job_id
        else []
    )
    allowed = {e["id"] for e in job_evidence}
    findings = [
        f
        for f in all_of(s, "finding")
        if f["target_id"] == target_id
        and f["status"] == "verified"
        and (not job_id or bool(allowed.intersection(f["evidence_ids"])))
    ]
    if job_id:
        findings = [
            dict(f, evidence_ids=[i for i in f["evidence_ids"] if i in allowed])
            for f in findings
        ]
    lines = [
        f"# {target['name']} 漏洞报告",
        "",
        "漏洞条目仅包含人工确认且关联证据的发现。验证附录记录行为观察，不等同于已确认漏洞。测试受授权范围、预算及模板覆盖限制。",
        "",
    ]
    evidence_ids = set()
    if job:
        lines += [
            "## 任务执行摘要",
            f"任务：{job['id']}",
            f"状态：{job['status']}；实际预留请求：{job['used']} / {job['request_budget']}",
            f"计划接口：{len(job['endpoint_ids'])}；请求证据：{len(job_evidence)}",
            "未请求、失败及不适用的检查不视为通过。",
            f"已发送：{sum(bool(e.get('sent_at')) for e in job_evidence)}；完成：{sum(e.get('state') == 'complete' for e in job_evidence)}；未请求接口：{sum(not any(e.get('endpoint_id') == ident for e in job_evidence) for ident in job['endpoint_ids'])}",
            "",
        ]
        if job.get('is_run'):
            lines.append(f"本次检查包含 {job['job_count']} 个内部检测步骤；接口发现已预留 {job.get('discovery_used', 0)} 次请求，未重复计入检测证据数量。")
        for ident in job["endpoint_ids"]:
            endpoint = get(s, ident, "endpoint")
            requested = [e for e in job_evidence if e["endpoint_id"] == ident]
            lines.append(
                f"- {endpoint['method']} {endpoint['url']}："
                + (
                    ", ".join(
                        f"{e['role']} / {e['state']} / HTTP {e.get('status', '—')}"
                        for e in requested
                    )
                    if requested
                    else "未请求"
                )
            )
        evidence_ids.update(allowed)
        for check in all_of(s, "check"):
            if check.get("job_id") in member_ids:
                lines.append(
                    f"- 检查：{check['name']}；结果：{check['status']}；{check.get('detail', '')}"
                )
        verification_labels = {
            "behavior_confirmed": "对照行为已复现，影响待人工确认",
            "not_reproduced": "本次未复现，不代表安全",
            "observed": "已观察到部分行为，证据不足以确认",
            "inconclusive": "无法确定",
        }
        for verification in all_of(s, "verification"):
            if verification.get("job_id") not in member_ids:
                continue
            linked = [i for i in verification.get("evidence_ids", []) if i in allowed]
            lines += [
                "## 主动验证与回放记录",
                f"插件：{verification.get('plugin_id', '未记录')}；验证 ID：{verification['id']}",
                "结论：" + verification_labels.get(verification.get("status"), "历史记录未标明验证结论"),
                "判断依据：" + redact(str(verification.get("reason", "未记录"))),
                "复核条件：" + redact(json.dumps(verification.get("criteria", []), ensure_ascii=False)),
                "步骤：" + redact(json.dumps(verification.get("steps", []), ensure_ascii=False)),
                "局限：" + redact(json.dumps(verification.get("limitations", []), ensure_ascii=False)),
                "关联证据：" + ", ".join(linked),
                "行为复现不等于已验证漏洞；需要结合业务权限、数据敏感性与部署环境人工确认。",
            ]
    for f in findings:
        evidence_ids.update(f["evidence_ids"])
        lines += [
            f"## {f['title']}",
            f"目标：{origin(target)}",
            f"描述：{f['detail']}",
            f"前置条件与最小复现步骤：{f['explanation']}",
            f"影响：{f['impact']}",
            f"修复建议：{f['fix']}",
            "证据：" + ", ".join(f["evidence_ids"]),
            "局限：模板结果及响应摘要无法单独证明业务漏洞。",
            "",
        ]
    evidence = [get(s, ident, "evidence") for ident in sorted(evidence_ids)]
    for ev in evidence:
        lines.extend(
            [
                f"### 证据 {ev['id']}",
                "```json",
                json.dumps(ev, ensure_ascii=False, indent=2),
                "```",
            ]
        )
    markdown = "\n\n".join(lines)
    if fmt == "md":
        return markdown.encode(), "text/markdown; charset=utf-8"
    if fmt == "html":
        return (
            '<!doctype html><meta charset="utf-8"><title>漏洞报告</title><pre style="white-space:pre-wrap">'
            + html.escape(markdown)
            + "</pre>"
        ).encode(), "text/html; charset=utf-8"
    if fmt != "zip":
        raise HTTPException(400, "支持 md、html、zip")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        z.writestr("report.md", markdown)
        z.writestr("evidence.json", json.dumps(evidence, ensure_ascii=False, indent=2))
    return output.getvalue(), "application/zip"
