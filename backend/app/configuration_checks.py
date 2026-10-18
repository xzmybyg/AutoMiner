"""Passive response configuration checks; no additional requests."""

import re

_DOCUMENT = re.compile(r"\b(?:example|documentation|tutorial|sample code)\b|示例|教程|文档", re.I)
_INDEX = re.compile(r"<(?:title|h1)\b[^>]*>\s*Index of\s+[^<]+</(?:title|h1)>", re.I)
_DEBUG = re.compile(r'''["']?DEBUG["']?\s*[:=]\s*(?:true|1)\b|You're seeing this error because you have DEBUG = True|Werkzeug Debugger''', re.I)
_LIMIT = "仅分析已有响应；开发环境、反向代理和合法部署可能产生相同表现，需人工确认，不证明可利用漏洞，未命中不代表安全。"


def inspect_response(body: str, headers: dict):
    normalized = {k.lower(): v for k, v in headers.items() if isinstance(k, str)}
    mime = normalized.get("content-type", "")
    mime = mime.split(";", 1)[0].strip().lower() if isinstance(mime, str) else ""
    html = mime in {"text/html", "application/xhtml+xml"}
    text = html or mime.startswith("text/") or mime in {"application/json", "application/xml"} or mime.endswith(("+json", "+xml"))
    valid = isinstance(body, str)
    document = valid and bool(_DOCUMENT.search(body))
    directory = html and valid and not document and bool(_INDEX.search(body)) and bool(re.search(r'href\s*=\s*["\'][^"\']+["\']', body, re.I))
    debug = text and valid and not document and bool(_DEBUG.search(body))
    checks, signals = [], []
    for key, name, applicable, hit in [("configuration-directory-index", "目录索引响应线索", html, directory), ("configuration-debug-enabled", "明确调试配置线索", text, debug)]:
        checks.append({"id": key, "name": name, "status": "not_applicable" if not applicable else "inconclusive" if not valid else "hit" if hit else "not_detected", "detail": ("文档或示例已忽略。" if document else "检查明确响应标记，不推断其他路径可访问。") + _LIMIT})
        if hit:
            signals.append({"root": key, "title": name + "，待人工确认"})
    version = any(isinstance(normalized.get(k), str) and re.search(r"\b\d+\.\d+", normalized[k]) for k in ("server", "x-powered-by"))
    checks.append({"id": "configuration-server-version", "name": "服务版本披露审查", "status": "inconclusive" if version else "not_detected", "detail": "仅检查服务头中的版本格式；版本字符串可能伪造，不能据此判定组件漏洞。" + _LIMIT})
    missing = html and any(not normalized.get(k) for k in ("content-security-policy", "x-content-type-options", "referrer-policy"))
    checks.append({"id": "configuration-defense-headers", "name": "浏览器防护头配置审查", "status": "inconclusive" if html else "not_applicable", "detail": ("存在未显式声明的浏览器防护头，仅作为配置待复核；缺少头不等于漏洞。" if missing else "防护头存在也不能确认配置有效或应用安全。") + _LIMIT})
    if missing:
        signals.append({"root": "configuration-defense-headers", "title": "浏览器防护头配置待复核，待人工确认"})
    return checks, signals
