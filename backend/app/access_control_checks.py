"""Pairwise identity comparisons are leads, not permission decisions."""


def compare_responses(responses, has_accounts):
    matching = set()
    successful = [r for r in responses if r.get("state") == "complete"
                  and r.get("status") == 200 and r.get("body_sha256")]
    for index, first in enumerate(successful):
        for second in successful[index + 1:]:
            first_identity = first.get("account_id") or first.get("role", "anonymous")
            second_identity = second.get("account_id") or second.get("role", "anonymous")
            if first_identity != second_identity and first["body_sha256"] == second["body_sha256"]:
                matching.update((first["id"], second["id"]))
    status = "not_applicable" if not has_accounts else (
        "inconclusive" if any(r.get("state") != "complete" for r in responses)
        else "hit" if matching else "not_detected"
    )
    return {
        "name": "匿名与专用账号逐对响应摘要对比",
        "status": status,
        "detail": "未配置专用测试账号，未进行权限对比。" if not has_accounts else
        "逐对比较匿名和专用账号的成功响应，也比较同角色的不同账号。"
        "相同摘要仅为待确认线索，公开资源或登录页面也可能相同；不同摘要不代表权限正确。"
        "未修改资源标识、未枚举其他用户数据，仍需资源归属和权限矩阵人工确认。",
    }, [r["id"] for r in responses if r["id"] in matching] if has_accounts else []
