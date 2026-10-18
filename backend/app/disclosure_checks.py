"""Passive disclosure clues; matched secrets never leave this module."""

import re

_DOCUMENT = re.compile(r"\b(?:example|documentation|tutorial|sample code)\b|示例|教程|文档", re.I)
_SECRET = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |OPENSSH )?PRIVATE KEY)-----[\s\S]{16,12000}?-----END (?P=kind)-----|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{36}\b"
)
_FIELD = re.compile(r'''["']?(?:password|api_key|access_token)["']?\s*[:=]\s*["']([^"'\r\n]{8,200})["']''', re.I)
_PLACEHOLDER = re.compile(r"example|sample|placeholder|your[_ -]|changeme|redacted|dummy|test|\*{3}|^<|^\$", re.I)
_SOURCE = re.compile(r"(?m)^\s*(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY)\s*=\s*\S+|Traceback \(most recent call last\):|<\?php\s", re.I)
_LIMIT = "仅分析已有响应，未读取其他资源；线索待人工确认，未命中不代表安全。所有描述均不包含命中的秘密值。"


def inspect_response(body: str, headers: dict):
    mime = next((v for k, v in headers.items() if isinstance(k, str) and k.lower() == "content-type" and isinstance(v, str)), "").split(";", 1)[0].strip().lower()
    applicable = mime.startswith("text/") or mime in {"application/json", "application/xml", "application/xhtml+xml"} or mime.endswith(("+json", "+xml"))
    valid = isinstance(body, str)
    document = valid and bool(_DOCUMENT.search(body))
    secret = valid and not document and (bool(_SECRET.search(body)) or any(not _PLACEHOLDER.search(m.group(1)) for m in _FIELD.finditer(body)))
    source = valid and not document and bool(_SOURCE.search(body))
    checks, signals = [], []
    for key, name, hit in [("disclosure-secret-format", "明确凭证及私钥格式线索", secret), ("disclosure-source-config", "源码、配置及调试信息线索", source)]:
        status = "not_applicable" if not applicable else "inconclusive" if not valid else "hit" if hit else "not_detected"
        detail = ("响应类型不适用文本分析。" if not applicable else "响应内容无法解析。" if not valid else "已识别文档或示例，不生成发现。" if document else "检查明确格式和配置上下文；公开示例、测试凭证及正常错误也可能匹配，不能据此确认凭证有效或可利用。") + _LIMIT
        checks.append({"id": key, "name": name, "status": status, "detail": detail})
        if applicable and hit:
            signals.append({"root": key, "title": name + "，待人工确认"})
    return checks, signals
