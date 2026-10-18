"""Response-only authentication/session clues, without retaining credentials."""

import re
from http.cookies import CookieError, SimpleCookie


_SESSION = re.compile(r"session|(?:^|[_-])sid(?:$|[_-])|^jsessionid$|^phpsessid$|^auth(?:[_-]|$)|(?:access|refresh)[_-]?token|^jwt$", re.I)
_CSRF = re.compile(r"csrf|xsrf|authenticity|requestverification", re.I)


def inspect_response(body: str, headers: dict):
    """Aggregate hints only; absence of a hint never establishes security."""
    values, challenges = [], []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            values.extend(value if isinstance(value, (list, tuple)) else [value])
        elif key.lower() == "www-authenticate":
            challenges.extend(value if isinstance(value, (list, tuple)) else [value])
    count = no_http_only = no_secure = no_same_site = none_without_secure = 0
    ambiguous = False
    for value in values:
        # Folded headers cannot reliably preserve cookie boundaries; do not infer
        # flags from them. A comma in a normal Expires date is supported.
        if (not isinstance(value, str) or not value.strip()
                or re.search(r'[\r\n]|,(?=\s*[^\s=;,]+\s*=)|"[^"\r\n]*[,;]', value)):
            ambiguous = True
            continue
        parsed = SimpleCookie()
        try:
            parsed.load(value)
        except CookieError:
            ambiguous = True
            continue
        if len(parsed) != 1:
            ambiguous = True
            continue
        name, cookie = next(iter(parsed.items()))
        # Repeated flag declarations and malformed flag values are ambiguous.
        attrs = [part.strip().split("=", 1)[0].lower() for part in value.split(";")[1:]]
        if len(attrs) != len(set(attrs)) or any(
            re.match(r"\s*(?:secure|httponly)\s*=", part, re.I)
            for part in value.split(";")[1:]
        ) or cookie["samesite"].lower() not in {"", "lax", "strict", "none"}:
            ambiguous = True
            continue
        if not _SESSION.search(name) or _CSRF.search(name):
            continue
        count += 1
        no_http_only += not bool(cookie["httponly"])
        no_secure += not bool(cookie["secure"])
        no_same_site += not bool(cookie["samesite"])
        none_without_secure += cookie["samesite"].lower() == "none" and not cookie["secure"]
    signals = []
    detail = (
        f"按名称识别到 {count} 个疑似认证/会话 Cookie，{no_http_only} 个未显式声明 HttpOnly，"
        f"{no_secure} 个未显式声明 Secure，{no_same_site} 个未显式声明 SameSite，"
        f"{none_without_secure} 个声明 SameSite=None 且未见 Secure。"
        "名称推断不能确认 Cookie 用途，属性存在不证明会话安全。未提供请求协议；"
        "HTTP 本地开发环境可能未设置 Secure，不能直接判为漏洞。SameSite 默认策略和合法跨站用途需人工确认，"
        "部分应用需要脚本读取特定 Cookie；未保存 Cookie 名称或值，未修改或重放会话。"
    )
    if ambiguous:
        detail += " 存在合并或无法可靠解析的 Cookie 头，整体无法确定，不生成配置发现。"
    elif count and (no_http_only or no_secure or no_same_site or none_without_secure):
        signals.append({"root": "auth-session-cookie-config-clue", "title": "疑似会话 Cookie 属性配置线索，待人工确认"})
    checks = [{"id": "auth-session-cookie-config", "name": "认证/会话 Cookie 属性线索",
               "status": "inconclusive" if values else "not_applicable", "detail": detail}]
    basic = False
    for value in challenges:
        if not isinstance(value, str) or "\r" in value or "\n" in value:
            continue
        # A scheme name inside a quoted realm is data, not a challenge.
        schemes = re.sub(r'"(?:[^"\\]|\\.)*"', '""', value)
        if '"' in schemes.replace('""', ''):
            continue
        basic |= bool(re.search(r"(?:^|,)\s*Basic(?:\s|$)", schemes, re.I))
    auth_detail = "未观察到 HTTP 认证挑战头；无法据此确认认证方式或会话安全，未尝试登录或猜测凭证。"
    if challenges:
        auth_detail = "观察到 HTTP 认证挑战头；仅分析认证方案，未保存挑战参数、未发送凭证。"
        if basic:
            auth_detail += " 包含 Basic 方案，需人工确认 TLS、访问范围及凭证保护；没有请求协议上下文，不能判定明文传输。"
            signals.append({"root": "auth-session-basic-clue", "title": "HTTP Basic 认证配置线索，待人工确认"})
    checks.append({"id": "auth-session-challenge", "name": "HTTP 认证配置线索",
                   "status": "inconclusive" if challenges else "not_detected", "detail": auth_detail})
    return checks, signals
