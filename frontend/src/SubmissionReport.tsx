import { useEffect, useRef, useState } from "react";

type Props = { findings: any[]; api: (path: string, body?: unknown, method?: string) => Promise<any>; token: string };
export default function SubmissionReport({ findings, api, token }: Props) {
  const [picked, setPicked] = useState("");
  const findingId = findings.some(f => f.id === picked) ? picked : findings[0]?.id || "";
  const [data, setData] = useState<any>(null);
  const [fields, setFields] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [dirty, setDirty] = useState(false);
  const apiRef = useRef(api); apiRef.current = api;
  useEffect(() => {
    let alive = true;
    setFields(null); setData(null); setError(""); setNotice(""); setDirty(false);
    if (findingId) void apiRef.current(`/findings/${findingId}/submission-draft`).then(value => { if (alive) { setData(value); setFields(value.fields); } }).catch(e => { if (alive) setError(String(e)); });
    return () => { alive = false; };
  }, [findingId]);
  const update = (key: string, value: any) => { setFields((old: any) => ({ ...old, [key]: value, ...(key === "exclusive_src" && value ? { category: "Web漏洞" } : {}) })); setDirty(true); setNotice(""); };
  const save = async (format?: "md" | "html") => {
    setBusy(true); setError("");
    try {
      const value = await api(`/findings/${findingId}/submission-draft`, fields, "PUT");
      setData(value); setFields(value.fields); setDirty(false); setNotice("草稿已保存到本地，未提交平台。");
      if (format) {
        const response = await fetch(`/api/findings/${findingId}/submission-export?format=${format}`, { headers: { "X-API-Key": token } });
        if (!response.ok) throw new Error("导出失败，草稿已保存，可稍后重试。");
        const url = URL.createObjectURL(await response.blob()); const a = document.createElement("a");
        a.href = url; a.download = `平台提交草稿-${findingId.slice(0, 8)}.${format}`; a.click(); URL.revokeObjectURL(url);
      }
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };
  const text = (key: string, title: string, long = false, maxLength = 2000) => <label key={key}>{title}{long ? <textarea rows={key === "details" ? 12 : 4} maxLength={maxLength} value={fields[key]} onChange={e => update(key, e.target.value)} /> : <input maxLength={maxLength} value={fields[key]} onChange={e => update(key, e.target.value)} />}</label>;
  const select = (key: string, title: string, options: string[], disabled = false) => <label>{title}<select disabled={disabled} value={fields[key]} onChange={e => update(key, e.target.value)}>{options.map(o => <option key={o} value={o}>{o || "请选择"}</option>)}</select></label>;
  return <section className="panel" aria-label="平台提交版报告">
    <h2>平台提交版 · 本地草稿</h2><p>按你提供的表单整理单条发现，保存后可导出 Markdown 或 HTML。不会自动提交、勾选协议或把线索改成已确认漏洞。</p>
    <label>选择要整理的发现<select disabled={busy} value={findingId} onChange={e => { if (!dirty || window.confirm("当前修改尚未保存，确定切换发现？")) setPicked(e.target.value); }}>{findings.map(f => <option key={f.id} value={f.id}>{f.title} · {f.id.slice(0, 8)}</option>)}</select></label>
    {!findingId && <p>当前范围没有发现。请先完成检查或录入人工证据。</p>}
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    {fields && <fieldset disabled={busy}>
      <legend>提交信息{dirty ? " · 有未保存修改" : data.saved_at ? " · 已保存" : " · 尚未保存"}</legend>
      <p className="muted">权重、等级、活动与厂商信息须自行核实。专属 SRC 固定使用 Web漏洞；域名请核实为平台要求的标准主域名。行业和地区填写平台当前选项，应用不猜测。</p>
      <label className="check"><input type="checkbox" checked={fields.exclusive_src} onChange={e => update("exclusive_src", e.target.checked)} />专属 SRC</label>
      <div className="two">{text("vendor", "厂商／准确企业名称", false, 150)}{text("asset_scope", "厂商资产范围", false, 1000)}{text("domain", "域名或 IP（不含协议与路径）", false, 253)}{select("category", "漏洞类别", ["Web漏洞", "IoT漏洞", "工控漏洞", "操作系统及通用软件漏洞"], fields.exclusive_src)}{text("title", "漏洞标题（单位名称＋漏洞类型）", false, 200)}{text("kind", "漏洞类型分组", false, 60)}{select("subtype", "漏洞类型", ["", ...(data.types || [])])}{select("weight", "漏洞权重（自行核实）", ["", "0", "≥1"])}{select("severity", "漏洞等级（自行核实）", ["", "低危", "中危", "高危", "严重"])}{text("activity", "参与活动（选填）", false, 150)}{text("task", "参与任务（选填）", false, 150)}</div>
      <label>漏洞 URL（每行一个 HTTP(S) 地址，可多个）<textarea rows={3} value={fields.urls.join("\n")} onChange={e => update("urls", e.target.value.split(/\r?\n/))} onBlur={() => update("urls", fields.urls.map((u: string) => u.trim()).filter(Boolean))} /></label>
      {text("summary", "简要描述（概况及影响，不填具体漏洞 URL）", true)}
      {text("details", "详细细节：基础信息、前置条件、完整复现过程、相关 URL 与影响", true, 20000)}
      {text("screenshots", "复现截图／视频、厂商归属证明（填写说明和链接）", true)}
      {text("poc", "PoC／最小复现说明（使用实际验证内容，不自动生成攻击代码）", true, 5000)}
      {text("components", "使用到的组件与下载链接；未使用请注明", true)}
      {fields.category === "IoT漏洞" && <><h3>IoT 必填补充</h3>{text("binary_location", "触发对应二进制位置", true, 1000)}{text("target_config", "目标配置情况", true)}{text("research_environment", "研究环境：硬件购买链接，或仿真搭建与调试方法", true)}</>}
      {text("fix", "修复方案", true, 4000)}
      {text("attachments", "附件清单（不在这里填写完整漏洞详情）", true)}
      <p className="muted">附件由你在平台手工上传：根据提供的规则，仅 ZIP/RAR 且不超过 50 MB；大文件在细节中提供链接。组件／固件／视频可作附件，漏洞详情必须写入详细细节。应用不会上传附件。</p>
      <details className="disclosure"><summary>行业、地区与联系方式</summary><div className="two">{text("industry", "所属行业", false, 100)}{text("industry_class", "行业分类", false, 100)}{text("province", "省／自治区／直辖市", false, 60)}{text("city", "城市", false, 60)}{text("district", "区／县", false, 60)}{text("contact", "厂商联系方式（按输入保存在本地并导出）", false, 300)}</div></details>
      <label className="check"><input type="checkbox" checked={fields.anonymous} onChange={e => update("anonymous", e.target.checked)} />匿名提交意向（到平台提交时再确认）</label>
      <h3>提交前待补充与核对（按已保存版本检查）</h3><ul>{data.missing.map((m: string) => <li key={m}>{m}</li>)}</ul>{!data.missing.length && <p>字段已填写，仍需核实实际证据与平台当前规则。</p>}
      <p className="muted">保存与导出会脱敏正文中的凭证、个人信息；提交前核对脱敏结果。请在平台自行阅读并确认用户协议及隐私政策。</p>
      <div className="actions"><button onClick={() => void save()}>保存草稿</button><button className="secondary" onClick={() => void save("md")}>保存并导出 Markdown</button><button className="secondary" onClick={() => void save("html")}>保存并导出 HTML</button></div>
    </fieldset>}
  </section>;
}
