import { useEffect, useState } from "react";

type Props = {
  targetId: string;
  jobId: string | null;
  token: string;
};
const statuses: Record<string, string> = {
  verified: "人工标记确认，需结合证据", pending: "待人工确认", lead: "线索",
};
const terms = [
  ["规则命中", "发现了符合规则的现象，需要结合上下文判断，不等于攻击成功。"],
  ["未发现线索", "已读取的内容未命中规则，不代表其他内容或整个网站没有漏洞。"],
  ["无法判断 / 不适用", "信息不足或不符合检查条件，都不能当作检查通过。"],
  ["任务完成", "这项任务按计划结束，不是网站安全认证。"],
];

export default function ReadableReport({ targetId, jobId, token }: Props) {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [visit, setVisit] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setData(null); setError("");
    const query = jobId ? "?job_id=" + encodeURIComponent(jobId) : "";
    fetch(`/api/targets/${encodeURIComponent(targetId)}/report-summary${query}`, {
      headers: { "X-API-Key": token }, signal: controller.signal,
    }).then(async response => {
      if (!response.ok) throw new Error("无法读取报告，请刷新或检查本地连接。");
      return response.json();
    }).then(value => { if (!controller.signal.aborted) setData(value); })
      .catch(reason => { if (!controller.signal.aborted) setError(String(reason.message)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [targetId, jobId, token, visit]);
  if (loading) return <section className="panel" role="status">正在整理已有检查记录…</section>;
  if (error) return <section className="panel" role="alert">{error}<button onClick={() => setVisit(v => v + 1)}>重新读取报告</button></section>;
  if (!data) return null;
  const counts = data.counts;
  return <section className="panel readable-report" aria-label="易懂版报告">
    <div className="actions"><button onClick={() => setVisit(v => v + 1)}>刷新报告</button></div>
    <div className="report-conclusion"><h2>{data.headline}</h2>
      <p>这是已有检查结果的解释，不会发起新请求，也不判断网站是否已被入侵。</p>
      {counts.complete_responses === 0 && <p><strong>当前没有完整响应记录，不能据此评价网站安全。</strong></p>}
    </div>
    <div className="task-coverage" aria-label="本报告检查规模">
      <span>任务结束 <strong>{counts.completed_jobs} / {counts.jobs}</strong></span>
      <span>有发送记录的地址 <strong>{counts.requested_endpoints}</strong></span>
      <span>完整响应记录 <strong>{counts.complete_responses}</strong></span>
      <span>人工确认记录 <strong>{counts.confirmed_findings}</strong></span>
    </div>
    <p className="muted">这些数字是检查规模，不是安全分数或漏洞总数。请求结束不代表正文完整；{counts.truncated_responses} 条响应存在内容截断。</p>
    <h3>先看需要处理什么</h3>
    {data.advice.length === 0 && <p>当前没有可自动解释的配置命中。历史记录缺少检查明细时，不推断检查通过。</p>}
    {data.advice.map((item: any) => <details className="report-explanation" key={item.id}>
      <summary>{item.title}<span className="muted"> · 展开说明</span></summary>
      <p><strong>什么意思：</strong>{item.explanation}</p>
      <p><strong>交给维护人员：</strong>{item.action}</p>
      <p className="muted">共 {item.observations} 条命中记录，可能是不同地址上的重复现象，不等于同等数量的独立漏洞。</p>
    </details>)}
    <details className="report-explanation"><summary>查看发现记录与确认状态（{data.findings.length} 条）</summary>
      {data.findings.length === 0 ? <p>暂无发现记录；这不等于没有风险。</p> : data.findings.map((finding: any) => <p key={finding.id}>
        {finding.title} · <strong>{statuses[finding.status] || "历史状态待核对"}</strong>
      </p>)}
      <p className="muted">切到技术版可查看证据编号与人工审核入口。</p>
    </details>
    <h3>接下来怎么做</h3><ol>{data.next_steps.map((step: string) => <li key={step}>{step}</li>)}</ol>
    <h3>哪些事情还不能确定</h3><ul>{data.limitations.map((text: string) => <li key={text}>{text}</li>)}</ul>
    <details className="report-explanation"><summary>看懂原报告的状态</summary>
      <dl>{terms.map(([name, meaning]) => <div key={name}><dt><strong>{name}</strong></dt><dd>{meaning}</dd></div>)}</dl>
    </details>
  </section>;
}
