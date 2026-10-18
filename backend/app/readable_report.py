"""Deterministic plain-language reports, scoped to the same target/task as evidence."""
import html
import io
import json
import zipfile
from collections import Counter

from fastapi import HTTPException

from .security import capture_text
from .service import all_of, get

ADVICE = {
    'csp-policy': ('给网页增加资源允许名单', '网页缺少内容安全策略 CSP，浏览器少了一层资源加载约束。',
                   '请开发人员按实际资源设计策略，先只记录再启用，并检查图片和脚本是否正常。'),
    'hsts-policy': ('让浏览器记住使用加密连接', '响应没有声明 HSTS；这不表示本次 HTTPS 连接没有加密。',
                    '确认 HTTPS 和证书稳定后设置 HSTS，单独评估子域与预加载。'),
    'mime-policy': ('让浏览器不要猜文件类型', '缺少 MIME 嗅探限制设置，不等于已经存在脚本或上传漏洞。',
                    '核对资源类型后配置 X-Content-Type-Options: nosniff，并回归正常功能。'),
    'configuration-defense-headers': ('核对浏览器防护设置', '工具发现响应防护设置线索，需要结合页面用途判断。',
                    '让开发人员核对页面嵌入等限制，修改后验证设置与业务功能。'),
}
LIMITATIONS = [
    '只解读已保存的检查记录；任务完成不等于网站安全，未发现线索不等于排除漏洞。',
    '公开页面地址不一定是业务接口；没有检查证据的接口不能算已检查。',
    '响应线索模板不能替代登录态权限、业务流程、源代码或专项漏洞验证。',
    '本报告不判断网站是否已被入侵；该判断需要另行检查日志和入侵证据。',
]


def summary(s, target_id, job_id=None):
    target = get(s, target_id, 'target')
    from .scan_runs import history, scope
    job, member_ids, _ = scope(s, job_id, target_id) if job_id else (None, [], [])
    jobs = [job] if job else [j for j in history(s) if j.get('target_id') == target_id]
    evidence = [e for e in all_of(s, 'evidence') if e.get('target_id') == target_id and (not job_id or e.get('job_id') in member_ids)]
    ids = {e['id'] for e in evidence}
    findings = [f for f in all_of(s, 'finding') if f.get('target_id') == target_id
                and not f.get('merged_into') and (not job_id or ids.intersection(f.get('evidence_ids', [])))]
    confirmed = [f for f in findings if f.get('status') == 'verified' and f.get('evidence_ids')
                 and all(any(e['id'] == ident and e.get('state') == 'complete' for e in evidence)
                         for ident in f['evidence_ids'])]
    hits = Counter(c.get('id') for e in evidence if e.get('state') == 'complete'
                   for c in e.get('checks', []) if c.get('status') == 'hit')
    records = []
    for finding in findings:
        if finding.get('status') == 'false_positive':
            continue
        records.append(dict(id=finding['id'], title=capture_text(finding.get('title', '历史记录未命名')),
                            status=finding.get('status', 'lead'),
                            evidence_ids=[i for i in finding.get('evidence_ids', []) if i in ids]))
    verifications = [v for v in all_of(s, 'verification') if v.get('target_id') == target_id
                     and (not job_id or v.get('job_id') in member_ids)]
    complete = [e for e in evidence if e.get('state') == 'complete']
    advice = [dict(id=ident, title=value[0], explanation=value[1], action=value[2], observations=hits[ident])
              for ident, value in ADVICE.items() if hits[ident]]
    return dict(target_name=capture_text(target.get('name', '历史目标')), target_id=target_id, job_id=job_id,
        headline=('有人工确认记录，请结合证据查看影响。' if confirmed else
                  '有待确认的线索；目前不能据此认定存在可利用漏洞。' if records or hits else
                  '尚无人工确认的漏洞结论；这不等于已排除风险。'),
        counts=dict(jobs=len(jobs), completed_jobs=sum(j.get('status') == 'completed' for j in jobs),
                    evidence=len(evidence), complete_responses=len(complete),
                    requested_endpoints=len({e['endpoint_id'] for e in evidence if e.get('endpoint_id') and e.get('sent_at')}),
                    confirmed_findings=len(confirmed), pending_findings=sum(f.get('status') in ('pending','lead') for f in findings),
                    truncated_responses=sum(bool(e.get('truncated') or e.get('http_exchange', {}).get('response', {}).get('truncated')) for e in complete)),
        check_states=dict(Counter(c.get('status', 'unknown') for e in evidence for c in e.get('checks', []))),
        verification_states=dict(Counter(v.get('status', 'unknown') for v in verifications)),
        advice=advice, findings=records, limitations=LIMITATIONS,
        next_steps=['先让维护人员复核线索与关联证据，再按网站实际情况加固。',
                    '修改后复测防护设置，并检查文章、图片、登录等正常功能。',
                    '补齐接口清单、专用测试账号和权限说明后，再做业务与登录态检查。'])


def export(s, target_id, fmt, job_id=None):
    data = summary(s, target_id, job_id)
    counts = data['counts']
    lines = [f"# {data['target_name']} · 易懂版报告", '', data['headline'], '',
             '## 如何阅读', '先看结论和处理建议，再看检查范围。任务完成和响应数量都不是安全得分。', '',
             f"任务：{counts['completed_jobs']} / {counts['jobs']} 项完成；完整响应记录：{counts['complete_responses']} 条；"
             f"有发送记录的地址：{counts['requested_endpoints']} 个；人工确认记录：{counts['confirmed_findings']} 条。", '',
             '记录完整仅表示请求结束，正文可能截断；不表示业务漏洞已全面验证。', '', '## 处理建议']
    for item in data['advice']:
        lines += [f"### {item['title']}", item['explanation'], item['action'], '配置线索不是可利用漏洞证明。', '']
    if not data['advice']:
        lines.append('当前没有可自动解释的配置命中；历史记录缺少检查项时不能推断通过。')
    lines += ['', '## 发现记录（保留人工确认状态）']
    status = {'verified':'人工已标记确认，请复核证据', 'pending':'待确认', 'lead':'线索'}
    lines += [f"- {f['title']}：{status.get(f['status'], '历史状态待核对')}；关联证据：{', '.join(f['evidence_ids']) or '本范围无关联证据'}" for f in data['findings']]
    lines += ['', '## 下一步', *data['next_steps'], '', '## 检查局限', *data['limitations'],
              f"内容截断响应：{counts['truncated_responses']} 条。", '',
              '状态说明：规则命中=需复核的现象；未发现=已读内容未出现线索；不适用=当前条件不适合该检查；无法判断=信息不足。']
    markdown = '\n\n'.join(lines)
    if fmt == 'md':
        return markdown.encode(), 'text/markdown; charset=utf-8'
    if fmt == 'html':
        return ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>易懂版报告</title><style>body{max-width:960px;margin:32px auto;padding:24px;font:17px/1.8 sans-serif;background:#faf9f6}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}</style><pre>'
                + html.escape(markdown) + '</pre></html>').encode(), 'text/html; charset=utf-8'
    if fmt != 'zip':
        raise HTTPException(400, '支持 md、html、zip')
    from .scan_runs import scope
    _, member_ids, _ = scope(s, job_id, target_id) if job_id else (None, [], [])
    evidence = [e for e in all_of(s, 'evidence') if e.get('target_id') == target_id and (not job_id or e.get('job_id') in member_ids)]
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('report.md', markdown)
        archive.writestr('evidence.json', json.dumps(evidence, ensure_ascii=False, indent=2))
    return output.getvalue(), 'application/zip'
