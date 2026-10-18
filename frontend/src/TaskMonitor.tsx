import { useEffect, useRef, useState } from "react";

type Props = { jobId: string; models: any[]; api: (path: string, body?: unknown, method?: string) => Promise<any> };
const states: Record<string, string> = { off: "已关闭", watching: "观察事件中", analyzing: "正在解读", finished: "任务已结束", limit: "已达监测上限", error: "监测已停止" };

export default function TaskMonitor({ jobId, models, api }: Props) {
  const [monitor, setMonitor] = useState<any>(null);
  const [model, setModel] = useState("");
  const [budget, setBudget] = useState("0.10");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const apiRef = useRef(api);
  apiRef.current = api;
  useEffect(() => {
    let alive = true;
    let first = true;
    const refresh = async () => {
      try {
        const value = await apiRef.current(`/jobs/${jobId}/monitor`);
        if (!alive) return;
        setMonitor(value);
        if (first) { setModel(value.model_id || ""); setBudget(String(value.max_cost_usd ?? 0.10)); first = false; }
      } catch (e) { if (alive) setError(String(e)); }
    };
    void refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => { alive = false; window.clearInterval(timer); };
  }, [jobId]);
  const toggle = async () => {
    setBusy(true); setError("");
    try {
      const value = await api(`/jobs/${jobId}/monitor`, { enabled: !monitor?.enabled, model_id: model || null, max_cost_usd: Number(budget) }, "PUT");
      setMonitor(value);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };
  return <section className="task-monitor" aria-label="任务事件监测 Agent">
    <div className="task-monitor-heading"><h3>任务事件监测 Agent</h3>
      <button type="button" role="switch" aria-checked={!!monitor?.enabled} disabled={busy || !monitor || (!monitor.enabled && !model)} onClick={() => void toggle()}>
        {busy ? "保存中…" : monitor?.enabled ? "关闭监测" : "开启监测"}
      </button>
    </div>
    <p className="muted">独立观察本任务，每 5 秒检查新事件；AI 最快每 30 秒解读一次，最多 3 次。不增加扫描请求，不控制任务，也不判定漏洞。仅发送状态、数量和事件类型，不发送请求内容。</p>
    <div className="task-monitor-settings">
      <label>解读模型<select value={model} disabled={!!monitor?.enabled || busy} onChange={e => setModel(e.target.value)}><option value="">选择已保存的模型</option>{models.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}</select></label>
      <label>本任务监测费用上限（美元）<input type="number" min="0.001" max="1" step="0.001" value={budget} disabled={!!monitor?.enabled || busy} onChange={e => setBudget(e.target.value)} /></label>
    </div>
    {!models.length && <p>请先到“设置”保存模型连接。</p>}
    <p className="muted">{states[monitor?.state] || "默认关闭"} · 已调用 {monitor?.calls || 0} / 3 次 · 已预留 ${(monitor?.reserved_usd || 0).toFixed(3)}。预留不是实际扣费，重启或切换开关不重置额度。</p>
    {(error || monitor?.error) && <p role="alert">{error || monitor.error}</p>}
    <div aria-live="polite">{(monitor?.entries || []).map((entry: any, i: number) => <article key={`${entry.at}-${i}`}>
      <small className="muted">{new Date(entry.at * 1000).toLocaleString()} · AI 解读，需人工核实</small><p>{entry.summary}</p>
    </article>)}</div>
  </section>;
}
