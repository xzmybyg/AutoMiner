import json
import os
import re

from cryptography.fernet import Fernet


def cipher():
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise ValueError("请先设置 ENCRYPTION_KEY，再保存账号或模型密钥")
    return Fernet(key.encode())


def encrypt(value):
    return cipher().encrypt(json.dumps(value).encode()).decode()


def decrypt(value):
    return json.loads(cipher().decrypt(value.encode()))


def redact(text, secrets=()):
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])|(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])", "[CREDENTIAL REDACTED]", text)
    text = re.sub(
        r'(?im)((?:authorization|cookie|set-cookie|password|passwd|token|api[_-]?key|secret[_-]?key|database[_-]?url|secret)[\s"\x27:=]+)[^\r\n,;<]+',
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[EMAIL]", text)
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "[PHONE]", text)
    return text


HTTP_CAPTURE_LIMIT = 65536
_SENSITIVE = re.compile(
    r"authorization|cookie|password|passwd|token|api.?key|secret|session|credential|"
    r"private.?key|secret.?key|database.?url|email|phone|mobile|address|身份证|姓名|name|card|ssn",
    re.IGNORECASE,
)


def capture_text(text, secrets=()):
    """Redact before persistence, including structured JSON and multiline keys."""
    for secret in sorted((str(s) for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
        r"(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|$)",
        "[PRIVATE KEY REDACTED]",
        text,
        flags=re.DOTALL,
    )
    try:
        value = json.loads(text)
    except RecursionError:
        return "[OMITTED: deeply nested JSON]"
    except (ValueError, TypeError):
        value = None
    else:

        def clean(item):
            if isinstance(item, dict):
                return {
                    k: "[REDACTED]" if _SENSITIVE.search(k) else clean(v)
                    for k, v in item.items()
                }
            if isinstance(item, list):
                return [clean(v) for v in item]
            return redact(item, secrets) if isinstance(item, str) else item

        try:
            return json.dumps(clean(value), ensure_ascii=False)
        except RecursionError:
            return "[OMITTED: deeply nested JSON]"
    text = re.sub(
        r"""(?im)(["']?(?:"""
        + _SENSITIVE.pattern
        + r""")["']?\s*[:=]\s*)(?:"[^"\r\n]*(?:"|$)|'[^'\r\n]*(?:'|$)|[^\r\n,;<]+)""",
        r"\1[REDACTED]",
        text,
    )
    return redact(text, secrets)


def http_exchange(url, result=None, secrets=()):
    """Bounded, redacted capture; missing/unsupported content is explicit."""
    secrets = tuple(secrets) + tuple(
        s.split(" ", 1)[1] for s in secrets if s and " " in s
    )
    secrets += tuple(
        part.split("=", 1)[1].strip()
        for s in secrets
        for part in s.split(";")
        if "=" in part and part.split("=", 1)[1].strip()
    )
    budget = HTTP_CAPTURE_LIMIT

    def bounded(text, limit):
        encoded = text.encode("utf-8")
        return encoded[:limit].decode("utf-8", errors="ignore"), len(encoded) > limit

    def headers(values):
        nonlocal budget
        kept, size, clipped = {}, 0, False
        for key, value in list(values.items())[:256]:
            key = str(key)[:256]
            value = (
                "[REDACTED]"
                if _SENSITIVE.search(key)
                else capture_text(str(value), secrets)
            )
            value, cut = bounded(value, min(2048, max(0, 16384 - size)))
            size += len(key.encode()) + len(value.encode())
            if size > 16384:
                clipped = True
                break
            kept[key] = value
            clipped |= cut
        budget -= size
        return kept, clipped or len(values) > 256

    safe_url, url_cut = bounded(capture_text(url, secrets), 4096)
    budget -= len(safe_url.encode())
    req_headers, req_cut = headers((result or {}).get("request_headers", {}))
    request_part = {
        "method": "GET",
        "url": safe_url,
        "url_truncated": url_cut,
        "headers": req_headers,
        "headers_truncated": req_cut,
        "body": "",
        "body_bytes": 0,
        "truncated": False,
        "body_state": "absent" if result else "not_captured",
    }
    if result is None:
        request_part["headers_state"] = "not_captured"
        response_part = {
            "status": None,
            "headers": {},
            "body": "",
            "body_bytes": None,
            "truncated": False,
            "body_state": "not_captured",
        }
    else:
        resp_headers, head_cut = headers(result.get("headers", {}))
        lower = {k.lower(): v for k, v in result.get("headers", {}).items()}
        content_type = lower.get("content-type", "").split(";")[0].strip().lower()
        textual = (
            content_type.startswith("text/")
            or content_type
            in (
                "application/json",
                "application/xml",
                "application/javascript",
                "application/x-javascript",
                "application/x-www-form-urlencoded",
            )
            or content_type.endswith(("+json", "+xml"))
        )
        state = "captured"
        if lower.get("content-encoding", "identity").lower() not in ("", "identity"):
            state = "omitted_encoded"
        elif not textual:
            state = "omitted_non_text"
        body, cut = (
            bounded(capture_text(result.get("body", ""), secrets), max(0, budget))
            if state == "captured"
            else ("", False)
        )
        response_part = {
            "status": result["status"],
            "headers": resp_headers,
            "headers_truncated": head_cut,
            "body": body,
            "body_bytes": result.get(
                "body_bytes", len(result.get("body", "").encode())
            ),
            "truncated": result.get("truncated", False) or cut,
            "body_state": state,
        }
    return {
        "request": request_part,
        "response": response_part,
        "redacted": True,
        "capture_limit_bytes": HTTP_CAPTURE_LIMIT,
    }
