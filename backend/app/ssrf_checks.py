"""Inspect existing response text only; never resolve or request a supplied URL."""

import re
from html.parser import HTMLParser


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.text = []
        self.url_input = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "pre", "code"}:
            self.hidden += 1
        if tag == "input" and not self.hidden:
            fields = dict(attrs)
            name = fields.get("name") or ""
            self.url_input |= (fields.get("type") or "").lower() == "url" or bool(
                re.fullmatch(r"(?:url|uri|callback_url|webhook_url|image_url|target_url|fetch_url)", name, re.I)
            )

    def handle_endtag(self, tag):
        if tag in {"script", "style", "pre", "code"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


_ERROR = re.compile(
    r"requests\.exceptions\.(?:ConnectionError|ConnectTimeout|ReadTimeout|InvalidURL)\b|"
    r"urllib3\.exceptions\.(?:MaxRetryError|NewConnectionError|ConnectTimeoutError)\b|"
    r"httpx\.(?:ConnectError|ConnectTimeout|ReadTimeout|UnsupportedProtocol)\b|"
    r"GuzzleHttp\\Exception\\(?:ConnectException|RequestException)\b|"
    r"java\.net\.(?:ConnectException|UnknownHostException|SocketTimeoutException)\b|"
    r"(?:outbound|server[- ]side)\s+(?:HTTP\s+)?request\s+(?:blocked|denied)|"
    r"(?:服务端|服务器端)(?:出站|发起的)?(?:HTTP)?请求.{0,12}(?:被拒绝|被阻止)",
    re.I,
)
_DOCUMENT = re.compile(r"\b(?:example|documentation|tutorial|sample code)\b|示例|教程|文档", re.I)
_LIMIT = "仅分析已有响应，不提交 URL、不访问内网或回连。命中不能证明 SSRF；未命中不代表安全。"


def inspect_response(body: str, headers: dict):
    content_type = next((str(v) for k, v in headers.items() if k.lower() == "content-type"), "")
    mime = content_type.split(";", 1)[0].strip().lower()
    textual = mime.startswith("text/") or mime in {"application/json", "application/xml", "application/xhtml+xml", "application/problem+json"} or mime.endswith(("+json", "+xml"))
    if not textual:
        return [
            {"id": "ssrf-server-error", "name": "服务端出站请求错误线索", "status": "not_applicable", "detail": "响应类型不适用文本分析。" + _LIMIT},
            {"id": "ssrf-url-input", "name": "URL 输入入口审查", "status": "not_applicable", "detail": "响应类型不适用表单分析。" + _LIMIT},
        ], []

    page = _Page()
    is_html = mime in {"text/html", "application/xhtml+xml"}
    if is_html:
        page.feed(body)
        text = " ".join(page.text)
    else:
        text = body
    document = bool(_DOCUMENT.search(text))
    hit = bool(_ERROR.search(text)) and not document
    checks = [
        {"id": "ssrf-server-error", "name": "服务端出站请求错误线索", "status": "hit" if hit else "not_detected", "detail": "匹配明确服务端 HTTP 客户端异常或出站请求被拒绝文本；异常也可能来自固定后端依赖，需人工确认输入可控性。" + ("已识别文档或示例文本，不生成漏洞线索。" if document else "") + _LIMIT},
        {"id": "ssrf-url-input", "name": "URL 输入入口审查", "status": "inconclusive" if page.url_input else ("not_detected" if is_html else "not_applicable"), "detail": ("发现 URL 类表单字段，仅提示人工审查其用途；字段存在不说明服务器会发起请求。" if page.url_input else "未识别可审查的 URL 类表单字段；不覆盖脚本生成表单或 API 参数。") + _LIMIT},
    ]
    signals = [{"root": "ssrf-server-error", "title": "服务端出站请求错误线索，待人工确认 SSRF"}] if hit else []
    return checks, signals
