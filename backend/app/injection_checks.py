"""Passive error markers only: no payload generation or vulnerability confirmation."""

import re


_RULES = [
    (
        "database-error",
        "SQL 解析错误标记",
        r"You have an error in your SQL syntax|SQLSTATE\[[A-Z0-9]+\]|"
        r"ORA-009(?:00|04|07|11|17|23|33|36)|"
        r"(?:sqlite3\.(?:OperationalError|ProgrammingError)|SQLiteException):|"
        r"ERROR:\s+syntax error at or near|Unclosed quotation mark after the character string",
    ),
    (
        "template-error",
        "模板解析错误标记",
        r"jinja2\.exceptions\.TemplateSyntaxError|django\.template\.exceptions\.TemplateSyntaxError|"
        r"freemarker\.core\.ParseException|Twig\\Error\\SyntaxError|"
        r"Liquid syntax error:",
    ),
    (
        "command-parser-error",
        "命令解析错误标记",
        r"(?:/bin/(?:ba)?sh|(?:ba)?sh):[^\r\n]{0,100}syntax error near unexpected token|"
        r"is not recognized as an internal or external command",
    ),
]


def inspect_errors(body):
    checks, signals = [], []
    for ident, name, pattern in _RULES:
        hit = bool(re.search(pattern, body, re.IGNORECASE))
        checks.append(
            {
                "id": ident,
                "name": name,
                "status": "hit" if hit else "not_detected",
                "detail": "仅匹配已有 GET 响应中的错误文本，不修改参数或发送注入载荷。"
                "错误可能来自文档或示例，命中不证明存在注入；未命中不代表安全。",
            }
        )
        if hit:
            signals.append({"root": ident, "title": name + "，待人工确认"})
    return checks, signals
