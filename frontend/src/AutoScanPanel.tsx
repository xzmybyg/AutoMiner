import { useEffect, useState } from "react";
type Props = {
  targetId: string;
  state: Record<string, any[]>;
  api: (path: string, body?: unknown, method?: string) => Promise<any>;
  run: (fn: () => Promise<unknown>) => Promise<void>;
  busy: boolean;
  onReport: (targetId: string, jobId: string) => void;
  onTask: (jobId: string) => void;
  onAutoReport: (id: string) => void;
};
const statuses: Record<string, string> = {
  queued: "排队中", running: "运行中", completed: "已完成", stopped: "已停止",
  paused: "已暂停", blocked: "已阻断",
};
const phases: Record<string, string> = {
  discovering: "发现接口", planning: "模型安排检测", testing: "执行只读检测",
  completed: "流程结束",
};

export default function AutoScanPanel({ targetId, state, api, run, busy, onReport, onTask, onAutoReport }: Props) {
  const [preview, setPreview] = useState("");
  const [templates, setTemplates] = useState<any[]>([]);
  const [allowedTests, setAllowedTests] = useState<string[]>(["baseline"]);
  useEffect(() => { void api("/test-catalog").then(value => setTemplates((value.templates || []).filter((t: any) => !["access_verify", "both", "role_compare"].includes(t.id)))).catch(() => setTemplates([])); }, []);
  const rows = [...(state.auto_scan || [])].sort((a, b) => b.created_at - a.created_at);
  return <section className="panel">
    <h2>一键自动检测</h2>
    <p className="muted">选定已验证目标和已保存模型后，后台自动发现接口、安排允许的只读检测并关联本地报告。关闭页面不影响执行；桌面应用退出后流程停止，不会自动重放请求。</p>
    <p className="muted">模型按轮次提出计划，执行结果摘要返回模型后决定下一步；默认不发送接口网址和正文；开启语义分析后发送脱敏路径、有限响应片段和业务规则，凭证仍会过滤。每轮只能选取下方允许的模板，最多 3 轮，重复计划或没有新证据会停止。当前仅检测无查询参数的 GET 接口，发现结果不代表完整接口清单。费用按出口配置的价格上界预留。</p>
    <form onSubmit={(event) => {
      event.preventDefault();
      const data = new FormData(event.currentTarget);
      const body = {
        target_id: targetId, model_id: data.get("model"),
        request_budget: Number(data.get("budget")), discovery_budget: Number(data.get("discovery")),
        duration_seconds: Number(data.get("duration")), max_cost_usd: Number(data.get("cost")),
        max_rounds: Number(data.get("rounds")), allowed_test_types: allowedTests,
        include_semantic_context: data.get("semantic") === "on", context: String(data.get("context") || ""),
      };
      if ((event.nativeEvent as SubmitEvent).submitter?.getAttribute("value") === "preview") {
        void run(async () => setPreview(JSON.stringify(await api(`/targets/${targetId}/model-preview`, {model_id: body.model_id, endpoint_ids: state.endpoint.filter(e => e.target_id === targetId).slice(0, 30).map(e => e.id), context: body.context, include_semantic_context: body.include_semantic_context, max_cost_usd: body.max_cost_usd}), null, 2)));
      } else { void run(() => api("/auto-scans", body)); }
    }}>
      <label>已保存模型<select name="model" required defaultValue=""><option value="" disabled>选择 DeepSeek 或其他模型连接</option>{state.model.map(m => <option key={m.id} value={m.id}>{m.name} · {m.model}</option>)}</select></label>
      <div className="two">
        <label>总请求预算（含接口发现）<input name="budget" type="number" min="2" max="100" defaultValue="20" required /></label>
        <label>其中接口发现最多请求数<input name="discovery" type="number" min="1" max="20" defaultValue="5" required /></label>
        <label>总时限（秒）<input name="duration" type="number" min="30" max="1800" defaultValue="300" required /></label>
        <label>模型费用上限（美元）<input name="cost" type="number" min="0.01" max="5" step="0.01" defaultValue="0.10" required /></label>
        <label>最多检测轮数<input name="rounds" type="number" min="1" max="3" defaultValue="2" required /></label>
      </div>
      <label className="check"><input name="semantic" type="checkbox" />启用 AI 语义分析（发送脱敏路径、业务规则与响应片段）</label>
      <label>业务规则与预期权限<textarea name="context" rows={3} placeholder="例如：草稿仅作者可见；仅使用合成测试数据" /></label>
      <p className="muted">预览展示当前已登记接口；发现新接口后，每轮发送内容会随证据更新。脱敏不能保证消除所有个人信息，请仅使用测试数据。</p>
      <button value="preview" disabled={busy || !targetId || !state.model.length || !state.endpoint.some(e => e.target_id === targetId)}>预览当前语义上下文</button>
      {preview && <details open><summary>发送内容预览</summary><pre>{preview}</pre></details>}
      <fieldset className="inset-panel"><legend>允许模型安排的检查</legend>
        <p className="muted">默认只开放响应基线。CORS 验证每接口最多 3 次匿名 GET；其他被动模板每接口 1 次 GET。不提供任意命令、脚本或业务写入。</p>
        <div className="auto-template-options">{(templates.length ? templates : [{ id: "baseline", name: "响应基线" }, { id: "cors_verify", name: "CORS 行为验证（主动）" }]).map(t => <label className="check" key={t.id}><input type="checkbox" checked={allowedTests.includes(t.id)} onChange={e => setAllowedTests(old => e.target.checked ? [...old, t.id] : old.filter(id => id !== t.id))} />{t.title || t.name || t.id}</label>)}</div>
        {!allowedTests.length && <p role="alert">至少选择一种允许的检查。</p>}
      </fieldset>
      <button className="primary" disabled={busy || !targetId || !state.model.length || !allowedTests.length}>开始自动检测</button>
    </form>
    <h3>自动流程记录</h3>
    {!rows.length && <p className="muted">暂无自动流程。进度与结果保存在本机，每 4 秒更新。</p>}
    {rows.map(row => <article className="panel" key={row.id}>
      <strong>{state.target.find(t => t.id === row.target_id)?.name || "历史目标"} · {row.id.slice(0, 12)}</strong>
      <p>{statuses[row.status] || row.status} · {phases[row.phase]} · 已用 {row.used} / {row.request_budget} 次</p>
      <p className="muted">{new Date(row.created_at * 1000).toLocaleString()} · {row.planned_interfaces ? `计划检测 ${row.planned_interfaces} 个接口` : "检测计划尚未生成"}</p>
      <p className="muted">轮次 {(row.rounds || []).length} / {row.max_rounds || 1} · 累计模型费用上界预留 ${Number(row.model_budget_reserved || 0).toFixed(4)} / ${Number(row.max_cost_usd || 0).toFixed(2)}（预留不等于实际账单）</p>
      {row.review_status && <p>AI 最终证据分析：{row.review_status === "completed" ? "已完成（待人工确认）" : row.review_status === "running" ? "分析中" : row.review_error}</p>}
      {(row.assessments || []).map((a: any, i: number) => <details key={`final-${i}`}><summary>AI 假设：{a.hypothesis}</summary><p>观察：{a.observation}</p><p>还需验证：{a.missing_evidence}</p><p>接口 {a.endpoint_id} · 证据 {a.evidence_ids.join("、") || "暂无"}</p></details>)}
      {row.stop_reason && <p>停止原因：{row.stop_reason}</p>}
      {(row.rounds || []).map((round: any) => <details className="task-endpoint" key={round.number}>
        <summary>第 {round.number} 轮 · {statuses[round.status] || round.status} · 计划 {round.proposals?.length || 0} 项</summary>
        {round.semantic_context && <details><summary>本轮实际发送的脱敏语义上下文</summary><pre>{JSON.stringify(round.semantic_context, null, 2)}</pre></details>}
        <p className="muted">本轮模型费用上界预留 ${Number(round.model_budget_reserved || 0).toFixed(4)}</p>
        {(round.assessments || []).map((a: any, i: number) => <div className="inset-panel" key={`analysis-${i}`}><strong>AI 假设 · 待确认</strong><p>{a.hypothesis}</p><p>观察：{a.observation}</p><p>还需验证：{a.missing_evidence}</p><p className="muted">接口 {a.endpoint_id} · 证据 {a.evidence_ids.join("、") || "暂无"}</p></div>)}
        {(round.proposals || []).map((p: any, i: number) => <p key={i}><strong>{templates.find(t => t.id === p.test_type)?.title || p.test_type}</strong> · 接口 {String(p.endpoint_id).slice(0, 12)} · 请求预算 {p.request_budget}<br /><span className="muted">预期证据：{p.expected_evidence || "见任务检查记录"}</span></p>)}
        {round.actual_summary && (typeof round.actual_summary === "string" ? <p>{round.actual_summary}</p> : <div className="task-coverage">
          <span>本轮已发送 <strong>{round.actual_summary.sent_requests || 0}</strong> 次</span>
          <span>完整响应 <strong>{round.actual_summary.completed_requests || 0}</strong> 条</span>
          <span>检查结果 <strong>{round.actual_summary.checks?.length || 0}</strong> 条</span>
          <span>独立验证 <strong>{round.actual_summary.verifications?.length || 0}</strong> 条</span>
        </div>)}
        <div className="auto-round-actions">{(round.job_ids || []).map((id: string) => <button className="secondary" key={id} onClick={() => onTask(id)}>查看检测步骤 {id.slice(0, 12)}</button>)}</div>
      </details>)}
      {row.error && <p role="status">{row.error}</p>}
      <div className="actions">
        {["queued", "running"].includes(row.status) && <>
          <button disabled={busy} onClick={() => void run(() => api(`/auto-scans/${row.id}/pause`, {}))}>暂停流程</button>
          <button disabled={busy} onClick={() => void run(() => api(`/auto-scans/${row.id}/stop`, {}))}>停止流程</button>
        </>}
        <button className="secondary" onClick={() => onTask(row.id)}>查看本次检查</button>
        <button className="secondary" onClick={() => onReport(row.target_id, row.id)}>查看本次检查报告</button>
        {row.report_id && <button onClick={() => onAutoReport(row.id)}>下载完整流程报告</button>}
      </div>
    </article>)}
  </section>;
}
