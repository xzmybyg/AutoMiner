"""Bounded response-only XML review; never parse XML, resolve entities or fetch URLs."""

import re
from html.parser import HTMLParser


_LIMIT = "仅分析已有响应，不解析 XML、不解析外部实体、不读取文件或回连；命中需人工确认，未命中不代表安全。"
_MAX_TEXT = 1024 * 1024
_DOCUMENT = re.compile(r"\b(?:example|documentation|tutorial|sample\s+code)\b|示例|教程|文档", re.I)
_ERROR = re.compile(
    r"\bfailed\s+to\s+load\s+external\s+entity\b|"
    r"\bexternal\s+(?:parameter\s+)?entity\b[^\r\n]{0,160}"
    r"\b(?:access\s+denied|not\s+allowed|disabled|forbidden|blocked|could\s+not\s+be\s+resolved)\b|"
    r"\baccessExternalDTD\b[^\r\n]{0,160}\b(?:restriction|not\s+allowed|denied)\b|"
    r"\bXMLSyntaxError\b[^\r\n]{0,160}\b(?:external\s+entity|external\s+DTD)\b|"
    r"(?:外部实体|外部\s*DTD)[^\r\n]{0,60}(?:解析失败|加载失败|被禁用|禁止访问)",
    re.I,
)
_DECLARATION = re.compile(
    r"<!DOCTYPE\s+[\w:.-]+\s+(?:SYSTEM\s+['\"]|PUBLIC\s+['\"])|"
    r"<!ENTITY\s+(?:%\s*)?[\w:.-]+\s+(?:SYSTEM\s+['\"]|PUBLIC\s+['\"])",
    re.I,
)


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = []
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "pre", "code", "template"}:
            self.hidden.append(tag)

    def handle_endtag(self, tag):
        if tag in self.hidden:
            del self.hidden[self.hidden.index(tag):]

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def inspect_response(body: str, headers: dict):
    """Return review checks and unconfirmed leads without copying response values."""
    checks = [
        {"id": "xxe-parser-error", "name": "XML 外部实体解析错误线索", "status": "not_detected", "detail": ""},
        {"id": "xxe-external-declaration", "name": "XML 外部实体声明审查", "status": "not_detected", "detail": ""},
    ]
    if not isinstance(body, str) or not isinstance(headers, dict):
        for check in checks:
            check.update(status="inconclusive", detail="响应数据格式不完整，无法分析。" + _LIMIT)
        return checks, []
    content_type = next((str(v) for k, v in headers.items() if str(k).lower() == "content-type"), "")
    mime = content_type.split(";", 1)[0].strip().lower()
    textual = mime.startswith("text/") or mime in {"application/json", "application/xml"} or mime.endswith(("+json", "+xml"))
    if not textual:
        for check in checks:
            check.update(status="not_applicable", detail="响应类型不适用文本分析。" + _LIMIT)
        return checks, []
    truncated = len(body) > _MAX_TEXT
    text = body[:_MAX_TEXT]
    # XHTML declarations are commonly normal browser doctypes, not server XML inputs.
    is_html = mime in {"text/html", "application/xhtml+xml"}
    if is_html:
        page = _VisibleText()
        page.feed(text)
        text = " ".join(page.parts)
    document = bool(_DOCUMENT.search(text))
    hit = bool(_ERROR.search(text)) and not document
    declaration = bool(_DECLARATION.search(text)) and not document and not is_html
    suffix = ("识别到文档或示例说明，不生成漏洞线索。" if document else "") + ("仅分析响应前 1 MiB。" if truncated else "") + _LIMIT
    checks[0].update(
        status="hit" if hit else ("inconclusive" if truncated else "not_detected"),
        detail=("发现明确 XML 外部实体加载或访问限制异常；可能来自已生效的防护，不能证明外部实体可利用或输入可控。" if hit else "未识别明确外部实体解析异常；普通 XML 语法错误不作为 XXE 线索。") + suffix,
    )
    checks[1].update(
        status="inconclusive" if declaration or truncated else ("not_applicable" if is_html else "not_detected"),
        detail=("发现 SYSTEM/PUBLIC 外部声明，仅提示人工审查来源与解析配置；声明本身不证明服务端解析或存在 XXE。" if declaration else "未识别可审查的 XML 外部声明；HTML 文档类型声明不作为 XXE 证据。") + suffix,
    )
    signals = [{"root": "xxe-parser-error", "title": "XML 外部实体解析错误线索，待人工确认 XXE"}] if hit else []
    return checks, signals
