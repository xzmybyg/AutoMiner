import { useEffect, useState } from "react";

type Props = {
  models: any[];
  api: (path: string, body?: unknown, method?: string) => Promise<any>;
  run: (fn: () => Promise<unknown>) => Promise<void>;
  busy: boolean;
};
const defaults = {
  name: "",
  base_url: "",
  model: "",
  api_key: "",
  local: false,
  max_output_tokens: 800,
};
const initialSettings = {
  MODEL_CLOUD_BASE_URLS: "",
  MODEL_LOCAL_BASE_URLS: "",
  MODEL_MAX_USD_PER_MILLION_TOKENS: 0,
};

export default function ModelManager({ models, api, run, busy }: Props) {
  const [editing, setEditing] = useState("");
  const [form, setForm] = useState(defaults);
  const [settings, setSettings] = useState(initialSettings);
  const [deleting, setDeleting] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => {
    void run(async () => {
      setSettings(await api("/model-settings"));
    });
  }, []);
  const reset = () => {
    setEditing("");
    setForm({ ...defaults });
  };
  return (
    <section className="panel">
      <h2>已保存的 AI 配置</h2>
      <p className="muted">
        连接与模型出口设置保存在本机，重启后可继续使用。密钥加密保存，不会回显。
      </p>
      <p role="status">{message}</p>
      {models.length === 0 && <p>尚未保存模型连接。</p>}
      {models.map((row) => (
        <article className="record" key={row.id}>
          <strong>{row.name}</strong>
          <p>
            {row.model} · {row.local ? "本地模型" : "云模型"}
          </p>
          <p style={{ overflowWrap: "anywhere" }}>{row.base_url}</p>
          <p className="muted">
            {row.has_api_key ? "密钥已保存" : "未保存密钥"}
          </p>
          <div className="actions">
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setEditing(row.id);
                setForm({
                  name: row.name,
                  base_url: row.base_url,
                  model: row.model,
                  local: row.local,
                  api_key: "",
                  max_output_tokens: row.max_output_tokens || 800,
                });
                setMessage("");
              }}
            >
              编辑
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => setDeleting(row.id)}
            >
              删除
            </button>
          </div>
          {deleting === row.id && (
            <div role="group" aria-label="确认删除模型连接">
              <p>删除“{row.name}”及其保存的密钥？历史建议保留。</p>
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    await api(`/model-configs/${row.id}`, undefined, "DELETE");
                    setDeleting("");
                    if (editing === row.id) reset();
                    setMessage("模型连接已删除");
                  })
                }
              >
                确认删除
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setDeleting("")}
              >
                取消
              </button>
            </div>
          )}
        </article>
      ))}
      <h3>{editing ? "编辑模型连接" : "新增模型连接"}</h3>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void run(async () => {
            await api(
              editing ? `/model-configs/${editing}` : "/model-configs",
              form,
              editing ? "PUT" : "POST",
            );
            reset();
            setMessage("模型连接已保存，重启后仍可使用");
          });
        }}
      >
        <label>
          名称
          <input
            required
            maxLength={200}
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
        </label>
        <label>
          兼容接口地址（含所需的 /v1）
          <input
            required
            type="url"
            value={form.base_url}
            onChange={(e) => setForm({ ...form, base_url: e.target.value })}
          />
        </label>
        <label>
          模型 ID
          <input
            required
            maxLength={200}
            value={form.model}
            onChange={(e) => setForm({ ...form, model: e.target.value })}
          />
        </label>
        <label>
          API 密钥
          <input
            type="password"
            autoComplete="new-password"
            value={form.api_key}
            onChange={(e) => setForm({ ...form, api_key: e.target.value })}
          />
        </label>
        <p className="muted">
          {editing
            ? "留空保留已保存的密钥；填写新密钥后会替换。"
            : "保存连接不会调用模型，也不会产生模型费用。"}
        </p>
        <label className="check">
          <input
            type="checkbox"
            checked={form.local}
            onChange={(e) => setForm({ ...form, local: e.target.checked })}
          />
          本地模型（允许接收脱敏后的业务描述）
        </label>
        <label>
          输出 token 上限
          <input
            type="number"
            min={100}
            max={2000}
            required
            value={form.max_output_tokens}
            onChange={(e) =>
              setForm({ ...form, max_output_tokens: Number(e.target.value) })
            }
          />
        </label>
        <button disabled={busy}>{busy ? "处理中…" : "保存连接"}</button>
        {editing && (
          <button type="button" disabled={busy} onClick={reset}>
            取消编辑
          </button>
        )}
      </form>
      <details>
        <summary>模型出口与费用设置</summary>
        <p className="muted">
          仅允许向下列明确受信任的地址调用模型；保存连接不会自动授信。每行填写一个完整接口地址，须与连接地址一致。
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void run(async () => {
              setSettings(await api("/model-settings", settings, "PUT"));
              setMessage("模型出口与费用设置已保存并立即生效");
            });
          }}
        >
          <label>
            受信任的云模型地址
            <textarea
              value={settings.MODEL_CLOUD_BASE_URLS.replaceAll(",", "\n")}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  MODEL_CLOUD_BASE_URLS: e.target.value
                    .split(/\r?\n/)
                    .join(","),
                })
              }
            />
          </label>
          <label>
            受信任的本地模型地址
            <textarea
              value={settings.MODEL_LOCAL_BASE_URLS.replaceAll(",", "\n")}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  MODEL_LOCAL_BASE_URLS: e.target.value
                    .split(/\r?\n/)
                    .join(","),
                })
              }
            />
          </label>
          <label>
            保守价格上界（美元 / 百万 token）
            <input
              type="number"
              required
              min={0}
              max={100000}
              step="any"
              value={settings.MODEL_MAX_USD_PER_MILLION_TOKENS}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  MODEL_MAX_USD_PER_MILLION_TOKENS: Number(e.target.value),
                })
              }
            />
          </label>
          <p className="muted">
            填写所有云模型输入、输出价格的保守上界；为 0
            时禁用云模型调用。实际计费由供应商决定。
          </p>
          <button disabled={busy}>保存出口设置</button>
        </form>
      </details>
    </section>
  );
}
