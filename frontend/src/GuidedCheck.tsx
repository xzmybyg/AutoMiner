import { useState } from "react";

type Props={target:any;state:Record<string,any[]>;api:(path:string,body?:unknown,method?:string)=>Promise<any>;run:(fn:()=>Promise<unknown>)=>Promise<void>;busy:boolean;onCreated:(id:string)=>void;onManage:()=>void;onAdvanced:()=>void};
export default function GuidedCheck({target,state,api,run,busy,onCreated,onManage,onAdvanced}:Props){
  const [preferences]=useState(()=>{try{return JSON.parse(localStorage.getItem(`check-preferences-${target?.id}`)||"{}");}catch{return {};}});
  const [step,setStep]=useState(1);
  const [purpose,setPurpose]=useState(preferences.purpose === "permissions" ? "permissions" : "public");
  const [accounts,setAccounts]=useState<string[]>([]);
  const endpoints=state.endpoint.filter(e=>e.target_id===target?.id&&e.method==="GET"&&e.executable);
  const [picked,setPicked]=useState<string[]>([]);
  const [budget,setBudget]=useState(preferences.budget || Math.max(1,Math.min(30,(target?.request_budget||30)-(target?.used||0))));
  const identities=state.account.filter(a=>a.target_id===target?.id);
  const selected=endpoints.filter(e=>picked.includes(e.id));
  const needed=selected.length*(purpose==="permissions"?1+accounts.length:1);
  const remaining=target?Math.max(0,target.request_budget-target.used):0;
  const ready=target?.verified&&!target.revoked&&!target.deleted&&target.expires_at>Date.now()/1000&&remaining>0;
  const validAccounts=accounts.length>0&&accounts.every(id=>identities.some(a=>a.id===id&&a.last_validation?.status==="valid"&&a.last_validation.version===target.version&&!a.credential_recovery_required));
  if(!target)return <section className="empty"><h2>先选择要检查的应用</h2><p>在上方“当前目标”选择已登记应用；尚未登记时先到“我的应用”添加。</p></section>;
  return <section className="panel">
    <h2>开始一次检查</h2><p>{target.name} · {target.scheme}://{target.host}:{target.port}</p>
    <ol className="guide-progress" aria-label="检查步骤">{["选择检查目的","确认账号与接口","确认并开始"].map((text,i)=><li key={text} aria-current={step===i+1?"step":undefined}>{i+1}. {text}</li>)}</ol>
    {!ready&&<p role="alert">目标尚未验证、已撤销或已过期，请先到“我的应用”处理授权。</p>}
    {step===1&&<>
      <label>检查目的<select value={purpose} onChange={e=>setPurpose(e.target.value)}><option value="public">公开页面检查（推荐，无需登录）</option><option value="permissions">后台身份对照（需要已验证账号）</option></select></label>
      <p>{purpose==="public"?"查看所选页面的响应配置和被动安全线索，不进行业务写入。":"比较匿名与选定账号访问相同接口时的响应。响应相同只是一条线索，需要结合权限规则确认。"}</p>
      <div className="actions"><button className="primary" disabled={!ready} onClick={()=>{setPicked(preferences.endpoint_ids?.length ? endpoints.filter(e=>preferences.endpoint_ids.includes(e.id)).slice(0,50).map(e=>e.id) : endpoints.slice(0,10).map(e=>e.id));setStep(2);}}>下一步</button><button className="secondary" onClick={onAdvanced}>使用高级检查</button></div>
    </>}
    {step===2&&<>
      {purpose==="permissions"&&<fieldset><legend>选择测试身份（最多 3 个）</legend>
        {identities.map(a=><label className="check" key={a.id}><input type="checkbox" checked={accounts.includes(a.id)} disabled={!accounts.includes(a.id)&&accounts.length>=3} onChange={e=>setAccounts(old=>e.target.checked?[...old,a.id]:old.filter(id=>id!==a.id))}/>{a.name} · {a.role} · {a.last_validation?.status==="valid"&&a.last_validation.version===target.version?"已验证":"需要验证"}</label>)}
        <button className="secondary" onClick={onManage}>管理账号 / 验证登录</button>{!validAccounts&&<p className="muted">继续前，请为所选账号验证登录状态。</p>}
      </fieldset>}
      <h3>本次检查哪些接口？</h3><p className="muted">仅列出已登记的 GET 接口，默认选择前 10 个。可取消不需要检查的地址。</p>
      {!endpoints.length&&<p>还没有可检查接口。<button className="secondary" onClick={onAdvanced}>发现或导入接口</button></p>}
      <div className="guide-endpoints">{endpoints.map(e=><label className="check" key={e.id}><input type="checkbox" checked={picked.includes(e.id)} onChange={v=>setPicked(old=>v.target.checked?[...old,e.id]:old.filter(id=>id!==e.id))}/><span>{e.url}</span></label>)}</div>
      <label>最多请求数<input type="number" min={1} max={Math.min(500,remaining)||1} value={budget} onChange={e=>setBudget(Number(e.target.value))}/></label>
      <p>已选 {selected.length} 个接口，预计 {needed} 次请求；目标剩余 {remaining} 次。</p>
      <div className="actions"><button className="secondary" onClick={()=>setStep(1)}>上一步</button><button className="primary" disabled={!selected.length||selected.length>50||needed>budget||budget>remaining||!Number.isInteger(budget)||budget<1||(purpose==="permissions"&&!validAccounts)} onClick={()=>setStep(3)}>下一步：确认范围</button></div>
    </>}
    {step===3&&<>
      <h3>确认本次检查</h3><p>将对 {selected.length} 个已选接口发送最多 {needed} 次 GET 请求，预算上限 {budget} 次。</p>
      <p>{purpose==="permissions"?`使用匿名身份及 ${accounts.length} 个已验证测试账号进行响应对照。` : "使用匿名身份检查响应配置与被动安全线索。"}</p>
      <p className="muted">不执行新增、编辑、发布、删除或压力测试。未命中线索不代表所有漏洞均已排除；结束后查看覆盖范围和待确认事项。</p>
      <details><summary>查看所选接口</summary>{selected.map(e=><p key={e.id}>{e.url}</p>)}</details>
      <div className="actions"><button className="secondary" disabled={busy} onClick={()=>setStep(2)}>上一步</button><button className="primary" disabled={busy||!ready||needed>remaining||(purpose==="permissions"&&!validAccounts)} onClick={()=>void run(async()=>{
        try{localStorage.setItem(`check-preferences-${target.id}`,JSON.stringify({purpose,budget,endpoint_ids:selected.map(e=>e.id)}));}catch{/* Preferences are optional. */}
        const job=await api("/jobs",{target_id:target.id,endpoint_ids:selected.map(e=>e.id),account_ids:purpose==="permissions"?accounts:[],endpoint_test_types:Object.fromEntries(selected.map(e=>[e.id,purpose==="permissions"?"role_compare":"baseline"])),request_budget:budget,duration_seconds:300});onCreated(job.id);
      })}>{busy?"正在创建…":"确认并开始检查"}</button></div>
    </>}
  </section>;
}
