"""Bounded, passive XSS leads from executable-looking response text only."""

import re
from html.parser import HTMLParser


_LIMIT = 1024 * 1024
_SOURCE = r"(?:(?:window\s*\.\s*)?location\s*\.\s*(?:search|hash|href)|document\s*\.\s*(?:URL|documentURI|referrer)|window\s*\.\s*name)\b"
_SOURCE_RE = re.compile(_SOURCE, re.I)
_SINK_RE = re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*=\s*(?!=)|\bdocument\s*\.\s*(?:write|writeln)\s*\(|\.\s*insertAdjacentHTML\s*\(", re.I)
_EXEC_RE = re.compile(r"\b(?:eval|setTimeout|setInterval|Function)\s*\(", re.I)
_JS_TYPES = {"", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.active = False
        self.inert = 0
        self.meta_csp = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"template", "pre", "code"}:
            self.inert += 1
        if self.inert:
            return
        if tag == "meta" and (attrs.get("http-equiv") or "").lower() == "content-security-policy":
            self.meta_csp = self.meta_csp or bool((attrs.get("content") or "").strip())
        if tag == "script":
            self.active = (attrs.get("type") or "").strip().lower() in _JS_TYPES and not attrs.get("src")
        for key, value in attrs.items():
            if key.startswith("on") and value:
                self.parts.append(value)

    def handle_endtag(self, tag):
        if tag == "script":
            self.active = False
        if tag in {"template", "pre", "code"} and self.inert:
            self.inert -= 1

    def handle_data(self, data):
        if self.active and not self.inert:
            self.parts.append(data)


def _code_only(text):
    # Preserve string boundaries but mask literal contents and comments. A quoted
    # example such as "el.innerHTML = location.hash" must not create a lead.
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch in "'\"`":
            quote = ch
            out.append(" ")
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = len(text) if end < 0 else end
            out.append("\n")
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _has_flow(code, sink):
    for match in sink.finditer(code):
        tail = code[match.end():match.end() + 512]
        # Only a local statement is considered, never infer variable taint.
        tail = re.split(r"[;\r\n]", tail, maxsplit=1)[0]
        if _SOURCE_RE.search(tail):
            return True
    return False


def inspect_response(body: str, headers: dict):
    headers = {str(k).lower(): str(v) for k, v in headers.items()}
    media = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    html = media in {"text/html", "application/xhtml+xml"}
    javascript = media in _JS_TYPES - {"", "module"}
    definitions = [
        ("xss-dom-source-sink", "DOM 不可信来源与 HTML 写入线索"),
        ("xss-dynamic-execution", "不可信来源与动态执行线索"),
        ("xss-csp-review", "CSP 配置复核"),
    ]
    if not (html or javascript):
        return ([{"id": ident, "name": name, "status": "not_applicable",
                  "detail": "响应未明确声明 HTML 或 JavaScript 类型，未作 XSS 文本检查；不代表安全。"}
                 for ident, name in definitions], [])
    text = body[:_LIMIT]
    parser = _Scripts()
    if html:
        parser.feed(text)
        parts = parser.parts
    else:
        parts = [text]
    codes = [_code_only(part) for part in parts]
    hits = [any(_has_flow(code, sink) for code in codes) for sink in (_SINK_RE, _EXEC_RE)]
    checks, signals = [], []
    for (ident, name), hit in zip(definitions[:2], hits):
        checks.append({"id": ident, "name": name, "status": "hit" if hit else "not_detected",
                       "detail": "仅检查已读取文本中同一局部语句的来源与危险调用，不执行脚本或发送载荷。"
                       "静态线索可能存在编码或净化等上下文，待人工确认；未命中不代表安全。"
                       "最多分析 1 MiB，未跟踪变量、外部脚本或模板字符串插值。"})
        if hit:
            signals.append({"root": ident, "title": name + "，待人工确认"})
    csp = bool(headers.get("content-security-policy", "").strip()) or parser.meta_csp
    checks.append({"id": definitions[2][0], "name": definitions[2][1],
                   "status": "not_applicable" if javascript else "inconclusive",
                   "detail": "未观察到 CSP，仅属配置待复核，不能判定 XSS。" if html and not csp else
                   "已观察到 CSP，未评估策略强度，不能据此判定安全。" if html else "独立脚本响应不判定页面 CSP。"})
    return checks, signals
