"""Read-only CSRF defence clues; never proves a CSRF vulnerability."""

import re
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie


_TOKEN = re.compile(r"csrf|xsrf|authenticity[_-]?token|requestverificationtoken", re.I)
_SESSION = re.compile(r"session|(?:^|[_-])sid(?:$|[_-])|^jsessionid$|^phpsessid$|auth|jwt|access[_-]?token", re.I)


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None
        self.ambiguous = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            if self.current is not None:
                self.ambiguous = True
            method = (attrs.get("method") or "get").strip().lower()
            if method not in {"get", "post", "dialog"}:
                self.ambiguous = True
            self.current = {"method": method, "token": False}
            self.forms.append(self.current)
        elif tag == "input":
            if attrs.get("form") is not None or attrs.get("formmethod") is not None:
                self.ambiguous = True
            if self.current is not None and (attrs.get("type") or "text").lower() == "hidden":
                if _TOKEN.search(attrs.get("name") or ""):
                    self.current["token"] = True
        elif tag == "button" and attrs.get("formmethod"):
            self.ambiguous = True

    def handle_endtag(self, tag):
        if tag == "form":
            if self.current is None:
                self.ambiguous = True
            self.current = None


def inspect_response(body: str, headers: dict):
    """Return aggregate checks and pending signals, without echoing input values."""
    checks, signals = [], []
    content_type = next((str(v).lower() for k, v in headers.items() if k.lower() == "content-type"), "")
    is_html = "text/html" in content_type or "application/xhtml+xml" in content_type
    if not content_type:
        is_html = bool(re.match(r"\s*(?:<!doctype\s+html|<html\b|<form\b)", body, re.I))
    form_detail = "非 HTML 响应，不进行表单线索检查。"
    form_status = "not_applicable"
    if is_html:
        parser = _Forms()
        try:
            parser.feed(body)
            parser.close()
            if parser.current is not None:
                parser.ambiguous = True
            mutating = [f for f in parser.forms if f["method"] == "post"]
            missing = sum(not f["token"] for f in mutating)
            form_status = "inconclusive"
            form_detail = (
                f"观察到 {len(parser.forms)} 个表单，其中 {len(mutating)} 个声明非 GET 方法，"
                f"{missing} 个未见常见隐藏防伪字段。仅为静态线索；字段存在不证明有效，缺少字段不证明 CSRF。"
                "无法据 HTML 确认服务端 Origin/Referer 校验、会话约束或 JavaScript 添加的防护；未提交表单。"
            )
            if parser.ambiguous:
                form_detail += " 表单结构或关联存在歧义，无法可靠判断。"
            elif missing:
                signals.append({"root": "csrf-form-token-clue", "title": "表单未见常见防伪字段线索，待人工确认"})
        except (ValueError, AssertionError):
            form_status = "inconclusive"
            form_detail = "HTML 无法可靠解析，不能确认 CSRF 防护；未提交表单。"
    checks.append({"id": "csrf-form-protection", "name": "表单防伪保护线索", "status": form_status, "detail": form_detail})

    cookie_values = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookie_values.extend(value if isinstance(value, (list, tuple)) else [value])
    session_count = missing = cross_site = 0
    ambiguous = False
    for value in cookie_values:
        # Do not split the comma within an Expires date. Folded cookies remain
        # conservative: quoted commas cannot safely be reconstructed here.
        if not isinstance(value, str) or re.search(r'"[^"\r\n]*[,;]', value):
            ambiguous = True
            continue
        for part in re.split(r",(?=\s*[^\s=;,]+\s*=)|[\r\n]+", value):
            if not part.strip():
                continue
            parsed = SimpleCookie()
            try:
                parsed.load(part)
            except CookieError:
                ambiguous = True
                continue
            if len(parsed) != 1:
                ambiguous = True
                continue
            name, cookie = next(iter(parsed.items()))
            if not _SESSION.search(name) or _TOKEN.search(name):
                continue
            session_count += 1
            same_site = cookie["samesite"].lower()
            if same_site not in {"", "lax", "strict", "none"}:
                ambiguous = True
            elif not same_site:
                missing += 1
            elif same_site == "none":
                cross_site += 1
    cookie_detail = (
        f"按名称识别到 {session_count} 个疑似会话 Cookie，{missing} 个未显式声明 SameSite，"
        f"{cross_site} 个声明 SameSite=None。名称推断可能不完整；未声明时浏览器可能采用默认限制，"
        "None 可能用于合法跨站场景。不能据此确认 CSRF，也不能以 Lax/Strict 判定安全。"
        "未保存 Cookie 名称或值，未发送跨站请求。"
    )
    if ambiguous:
        cookie_detail += " Cookie 头存在无法可靠解析的内容，策略无法确定。"
    elif missing or cross_site:
        signals.append({"root": "csrf-cookie-policy-clue", "title": "疑似会话 Cookie 跨站策略线索，待人工确认"})
    checks.append({"id": "csrf-cookie-policy", "name": "会话 Cookie 跨站策略线索", "status": "inconclusive" if cookie_values else "not_applicable", "detail": cookie_detail})
    return checks, signals
