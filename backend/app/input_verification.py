"""Three-request, anonymous GET comparisons with fixed non-executing markers."""
import re
from html.parser import HTMLParser
from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import uuid4

from .policy import Denied

MODES = {"sql_error_verify": "SQL 错误差异对照", "xss_reflection_verify": "HTML 输入反射对照", "redirect_verify": "开放重定向对照"}
LABELS = ("control_a", "input_probe", "control_b")
LIMITS = {
    "sql_error_verify": "只验证固定引号输入与数据库错误的关联，不读取数据、不进行盲注或确认 SQL 注入可利用性。",
    "xss_reflection_verify": "只验证惰性自定义 HTML 标记反射，不执行 JavaScript，不覆盖存储型或 DOM XSS，不能据此确认脚本执行。",
    "redirect_verify": "只验证响应 Location 是否指向固定 .invalid 标记地址，不跟随跳转、不解析或访问该域名。",
}


def validate(body, endpoints):
    selected = {ident for ident in body.endpoint_ids if body.endpoint_test_types.get(ident) in MODES}
    rules = body.model_dump().get("input_probe_rules", {})
    if set(rules) != selected:
        raise Denied("输入对照规则必须与所选主动对照接口一一对应")
    if selected and body.account_ids:
        raise Denied("输入对照首版仅允许匿名请求，不绑定账号")
    for ident in selected:
        endpoint = endpoints[ident]
        if endpoint["method"] != "GET" or urlsplit(endpoint["url"]).query or urlsplit(endpoint["url"]).fragment:
            raise Denied("输入对照仅允许已登记、无查询参数的只读 GET 接口")
        parameter = rules[ident]["parameter"]
        if re.search(r"password|passwd|token|secret|cookie|authorization|session|api.?key", parameter, re.I):
            raise Denied("不得对凭证或会话参数进行输入对照")


def prepare(job_id, endpoint_id, label):
    from .service import all_of, get
    from .store import Session
    if label not in LABELS:
        raise Denied("未知输入对照探针")
    with Session() as s:
        job = get(s, job_id, "job")
        endpoint = get(s, endpoint_id, "endpoint")
        mode = job.get("endpoint_test_types", {}).get(endpoint_id)
        rule = job.get("input_probe_rules", {}).get(endpoint_id)
        rows = [r for r in all_of(s, "verification") if r.get("job_id") == job_id and r.get("endpoint_id") == endpoint_id and r.get("plugin_id") == mode]
        if mode not in MODES or not rule or job["status"] != "running" or len(rows) != 1 or rows[0].get("completed_at"):
            raise Denied("输入探针不属于正在执行的固定验证组")
        nonce = rows[0].get("nonce", "")
        if not re.fullmatch(r"[a-f0-9]{32}", nonce):
            raise Denied("验证组标记无效")
        # Check persisted rules too; callers cannot bypass schema validation.
        from .schemas import InputProbeRule
        InputProbeRule.model_validate(rule)
        parts = urlsplit(endpoint["url"])
        if parts.query or parts.fragment or endpoint["method"] != "GET":
            raise Denied("输入探针不能覆盖已有参数")
        marker = "autominer_" + nonce
        redirect = "https://autominer-" + nonce + ".invalid/"
        if mode == "sql_error_verify":
            value = marker + ("'" if label == "input_probe" else "")
        elif mode == "xss_reflection_verify":
            value = f'<autominer-probe data-marker="{nonce}">{marker}</autominer-probe>' if label == "input_probe" else marker
        else:
            value = redirect if label == "input_probe" else "/"
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode({rule["parameter"]: value}), "")), mode, nonce, redirect if mode == "redirect_verify" and label == "input_probe" else None


class MarkerHTML(HTMLParser):
    def __init__(self, nonce):
        super().__init__()
        self.nonce = nonce
        self.inert = []
        self.hit = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noscript", "plaintext", "template"):
            self.inert.append(tag)
        if not self.inert and tag == "autominer-probe" and dict(attrs).get("data-marker") == self.nonce:
            self.hit = True

    def handle_endtag(self, tag):
        if tag in self.inert:
            self.inert = self.inert[:self.inert.index(tag)]


def observe(mode, nonce, result):
    from .injection_checks import inspect_errors
    headers = {k.lower(): v for k, v in result.get("headers", {}).items()}
    body = result.get("body", "")
    mime = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    encoded = headers.get("content-encoding", "identity").lower() not in ("", "identity")
    if mode == "sql_error_verify":
        checks, _ = inspect_errors(body)
        return {"applicable": not encoded and mime in ("text/html", "text/plain", "application/json", "application/problem+json"),
                "database_error": any(c["id"] == "database-error" and c["status"] == "hit" for c in checks)}
    if mode == "xss_reflection_verify":
        parser = MarkerHTML(nonce)
        parser.feed(body)
        return {"applicable": not encoded and mime in ("text/html", "application/xhtml+xml"), "html_marker": parser.hit,
                "text_marker": "autominer_" + nonce in body}
    return {"applicable": True, "redirect_marker": result.get("redirect_probe_match", False)}


def evaluate(mode, responses):
    if len(responses) != 3 or [e.get("probe_label") for e in responses] != list(LABELS):
        return "inconclusive", "固定三次对照未完成，不能推断通过或复现。"
    if any(e.get("state") != "complete" or e.get("truncated") or e.get("http_exchange", {}).get("response", {}).get("truncated") or e.get("http_exchange", {}).get("response", {}).get("headers_truncated") or not e.get("input_observation", {}).get("applicable") for e in responses):
        return "inconclusive", "响应不完整、被截断、压缩或类型不适用，无法判断。"
    a, probe, b = responses
    controls_ok = all(e.get("status") == 200 and not e.get("redirect_blocked") for e in (a, b))
    if mode == "redirect_verify":
        controls_ok = all(e.get("status") in (200, 301, 302, 303, 307, 308) and not e.get("redirect_blocked") for e in (a, b))
        hit = probe.get("status") in (301, 302, 303, 307, 308) and probe["input_observation"]["redirect_marker"]
    else:
        if any(e.get("redirect_blocked") or 300 <= e.get("status", 0) < 400 for e in responses):
            return "inconclusive", "对照发生跳转，不能可靠比较原接口。"
        key = "database_error" if mode == "sql_error_verify" else "html_marker"
        if mode == "sql_error_verify" and any(e["input_observation"].get(key) for e in (a, b)):
            return "inconclusive", "控制响应已包含数据库错误，无法将差异归因于探针。"
        hit = probe["input_observation"].get(key) is True and not any(e["input_observation"].get(key) for e in (a, b))
        if mode == "sql_error_verify":
            hit = hit and probe.get("status") in (200, 400, 500)
        else:
            hit = hit and probe.get("status") == 200
    if not controls_ok:
        return "inconclusive", "前后控制请求未成功或发生范围外跳转，缺少稳定阳性对照。"
    if hit:
        return "behavior_confirmed", {"sql_error_verify": "固定引号输入时出现数据库错误，前后控制均未出现；仅确认错误差异。", "xss_reflection_verify": "静态 HTML 解析在非惰性区域识别到固定标记标签；未执行浏览器，不证明 JavaScript 可执行。", "redirect_verify": "固定外部 .invalid 标记被返回为重定向 Location；跳转未跟随。"}[mode]
    expected_statuses = (200, 301, 302, 303, 307, 308) if mode == "redirect_verify" else (200, 400, 500)
    if probe.get("status") not in expected_statuses:
        return "inconclusive", "探针被拒绝或返回异常状态，无法排除防护、认证或瞬时错误的影响。"
    return "not_reproduced", "本次固定输入未复现所检查的行为，不代表已排除该类漏洞。"


def run(job_id, endpoint_id, mode):
    from .service import all_of, audit, create, execute, finding, get, locked, save
    from .store import now
    with locked() as s:
        job = get(s, job_id, "job")
        if mode not in MODES or job.get("endpoint_test_types", {}).get(endpoint_id) != mode or endpoint_id not in job["endpoint_ids"] or job["status"] != "running":
            raise Denied("输入验证不属于此运行任务")
        if any(v.get("job_id") == job_id and v.get("endpoint_id") == endpoint_id and v.get("plugin_id") == mode for v in all_of(s, "verification")):
            return
        row = create(s, "verification", {"job_id": job_id, "target_id": job["target_id"], "endpoint_id": endpoint_id, "plugin_id": mode,
            "nonce": uuid4().hex, "status": "inconclusive", "reason": "固定对照尚未完成，不自动重放。", "evidence_ids": [], "steps": [], "at": now(),
            "criteria": "前控制、固定探针、后控制三次独立取证", "limitations": LIMITS[mode]})
        audit(s, "verification_started", job_id, mode)
    responses = []
    error = None
    try:
        for label in LABELS:
            responses.append(execute(job_id, endpoint_id, input_probe=label))
    except Exception as exc:
        error = exc
    status, reason = evaluate(mode, responses)
    with locked() as s:
        row.update(status=status, reason=reason, evidence_ids=[e["id"] for e in responses],
            steps=[{"probe_label": e.get("probe_label"), "evidence_id": e["id"], "state": e["state"]} for e in responses], completed_at=now())
        save(s, row)
        audit(s, "verification_completed", job_id, mode + ":" + status)
        if status == "behavior_confirmed":
            finding(s, job, endpoint_id, MODES[mode] + "行为已复现，待核实影响", row["evidence_ids"], mode, reason + LIMITS[mode])
            fixes = {"sql_error_verify": "复核查询构造，使用参数绑定，避免向客户端暴露数据库错误。", "xss_reflection_verify": "结合输出上下文编码；需要 HTML 时使用可靠净化器，进一步验证输入来源与实际影响。", "redirect_verify": "重定向目标使用同站路径或精确允许名单，避免直接信任外部 URL 参数。"}
            for item in all_of(s, "finding"):
                if item.get("target_id") == job["target_id"] and item.get("endpoint_id") == endpoint_id and set(row["evidence_ids"]).intersection(item.get("evidence_ids", [])):
                    item["fix"] = fixes[mode]
                    save(s, item)
    if error:
        raise error
