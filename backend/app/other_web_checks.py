"""Header-only contextual leads; no Origin probes or redirect following."""

import re
from urllib.parse import urlsplit


_LIMIT = "仅分析已有响应，不发送 Origin 探针或跟随重定向；线索需人工结合请求上下文确认，未命中不代表安全。"


def inspect_response(body: str, headers: dict):
    definitions = [("web-frame-policy", "HTML 嵌入策略审查"), ("web-cors-policy", "CORS 响应策略审查"), ("web-redirect-reference", "重定向地址审查")]
    checks = [{"id": key, "name": name, "status": "not_detected", "detail": ""} for key, name in definitions]
    if not isinstance(body, str) or not isinstance(headers, dict):
        for c in checks:
            c.update(status="inconclusive", detail="响应格式不完整。" + _LIMIT)
        return checks, []
    h = {str(k).lower(): str(v).strip() for k, v in headers.items()}
    html = h.get("content-type", "").split(";", 1)[0].strip().lower() in {"text/html", "application/xhtml+xml"}
    csp = h.get("content-security-policy", "")
    ancestors = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
    frame = h.get("x-frame-options", "").upper() in {"DENY", "SAMEORIGIN"} or bool(ancestors and ancestors[1].strip() != "*")
    checks[0].update(status="not_applicable" if not html else ("not_detected" if frame else "inconclusive"), detail=("响应不是 HTML；不据此要求页面嵌入防护。" if not html else ("发现 X-Frame-Options 或限制性的 frame-ancestors 声明，仍需核对浏览器解析与页面用途。" if frame else "未识别限制性嵌入响应头，需结合页面敏感操作与预期嵌入用途审查；缺少响应头本身不证明点击劫持。")) + _LIMIT)
    origin = h.get("access-control-allow-origin", "")
    credential = h.get("access-control-allow-credentials", "").lower() == "true"
    contradiction = origin == "*" and credential
    null = origin.lower() == "null"
    checks[1].update(status="inconclusive" if contradiction or null else "not_detected", detail=("通配来源与凭证许可同时出现；浏览器拒绝此凭证跨源组合，不能视作可利用 CORS，需核对配置意图。" if contradiction else ("响应许可 null 来源；需核对调用场景、凭证及敏感响应，缺少请求 Origin 上下文不能证明可利用。" if null else "未识别指定 CORS 矛盾配置；没有请求 Origin、凭证及敏感数据上下文，不能验证来源反射或跨源读取。")) + _LIMIT)
    location = h.get("location", "")
    try:
        url = urlsplit(location)
        absolute = bool(url.netloc) or url.scheme.lower() in {"javascript", "data"}
    except ValueError:
        absolute = bool(location)
    checks[2].update(status="inconclusive" if absolute else "not_detected", detail=("发现绝对或特殊协议 Location；缺少响应状态、页面来源及输入可控证据，需人工确认重定向用途，不能判为开放重定向。" if absolute else "未识别绝对或特殊协议 Location；不证明重定向输入安全。") + _LIMIT)
    return checks, []
