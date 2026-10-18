# AutoMiner

本地单用户的授权安全测试工作台。React + TypeScript、FastAPI、SQLite（Windows）/ PostgreSQL（Docker）、独立 Worker 和执行/模型出口。

## Windows EXE 桌面版（无需 Docker）

统一启动入口为项目根目录 `AutoMiner.exe`（或 `启动AutoMiner.cmd`），构建产物位于 `release/AutoMiner.exe`；直接双击启动，无需安装 Python、Node.js、PostgreSQL 或 Docker。使用 Windows 10/11 x64 和 Microsoft Edge WebView2 Runtime。若缺少 WebView2，请从 [Microsoft 官方页面](https://developer.microsoft.com/microsoft-edge/webview2/) 安装 Evergreen Runtime；本 EXE 不包含该系统运行时，也没有数字签名或安装器。

桌面版使用 pywebview / WebView2 窗口，自动启动 API、执行网关、模型出口、Worker 四个独立进程。三个服务仅监听随机的 `127.0.0.1` 端口，临时会话密钥自动连接，不需要手工输入访问密钥。数据使用 SQLite，项目默认工作库为 `data/desktop/autominer.db`，用户级定位文件 `~/.autominer/workspace.json` 固定所有入口使用的位置，避免 AppData 虚拟化造成多份数据。凭证密钥使用 Windows DPAPI 按当前账户保护，保存在同一目录的 `credential-key.dpapi`。启动时配套备份数据库、密钥与设置；已有工作库或密钥缺失时停止启动，不自动创建空库。同一数据目录仅允许一个实例运行。

关闭桌面窗口后会先停止新任务，再终止所有后台进程。Windows Job Object 在主进程退出时清理子进程；异常中断的任务下次启动标记为已停止，未完成证据标记为中断，不会自动重放。退出前已经发送的 HTTP 请求无法撤回。

**原生进程不是操作系统网络沙箱。** 本版未创建 Windows 防火墙规则，不能替代 Docker 网络隔离；目标限制由受控执行器、精确范围检查和控制权验证执行。模型没有终端或任意工具执行入口，写入测试仍未开放。

### 测试你的 `http://localhost:5177/`

1. 启动 EXE，在“授权目标”选择“Windows 本机应用”，填写 `http`、`localhost`、`5177`、允许路径 `/`、有效期及请求预算，声明应用所有权。
2. 保存后展开“验证说明与挑战”。对于 Vite 项目，在被测项目创建 `public/.well-known/autominer-verification.txt`，内容为挑战值（可下载验证文件后放入该目录）。
3. 用浏览器访问 `http://localhost:5177/.well-known/autominer-verification.txt`，应只看到挑战值。开发服务器的 SPA 首页回退不能代替证明文件。
4. 点击“HTTP / 靶场验证”，通过后在顶部选择目标，进入“测试任务”导入接口，例如：

```json
{"requests":[{"method":"GET","url":"http://localhost:5177/"}]}
```

5. 配置预算，创建测试任务，查看“执行记录”和“发现与报告”。仅导入你已确认不会写入数据的接口。

`localhost`、`127.0.0.1` 与 `::1` 分别是不同授权主机，不能混用。原生模式只允许标准回环地址 `127.0.0.1` / `::1`，拒绝回环别名、DNS 解析到非回环、低于 1024 的端口、数据库/容器管理端口及 AutoMiner 自身服务端口。本机应用必须通过 HTTP 文件验证，不能用 DNS 或“靶场”声明绕过。IPv4/IPv6 只在 HTTP 发送前对已校验的回环地址尝试连接，不会重放已经发送的请求。

如果前端通过代理访问另一个端口的后端 API，只测试前端页面不能覆盖后端权限逻辑。后端端口需要单独登记并验证；代理执行的服务端请求不属于本工具的出站网络边界。

### 本地模型与云模型

在“设置”页面保存模型连接、可信模型基础地址及云端价格上界，立即生效并在重启后恢复。密钥加密保存，编辑时留空保留原密钥。工作库中的 `settings.json` 仅作为尚未在界面保存配置时的默认值，例如：

```json
{
  "model_cloud_base_urls": "https://your-provider.example/v1",
  "model_local_base_urls": "http://localhost:11434/v1",
  "model_max_usd_per_million_tokens": 0
}
```

`0` 关闭云端调用；请按供应商实际定价设置保守上界。此文件不要放 API 密钥，密钥通过界面录入并加密存储。不会自动读取或复制项目 `.env`。独立试运行可使用 `--data-dir` 指定隔离目录，不会改变默认工作库位置。

### 从源码构建 EXE

在 Windows 项目根目录运行：

```powershell
python -m venv .venv
.\scripts\build_windows.ps1
```

构建机需要 Python、Node.js；运行生成的 EXE 不需要。构建脚本安装固定版本桌面依赖、构建界面，再使用 PyInstaller 生成单文件无控制台 EXE，未打包 `.env`、数据库或项目凭证。构建后自动启动生成的 EXE 完成实际请求自检，失败即终止构建流程。

源码运行：`.\.venv\Scripts\python desktop/launcher.py`。发布包自检会使用指定目录及一次性合成 HTTP 服务，不测试用户真实应用：

```powershell
.\release\AutoMiner.exe --smoke-test --data-dir "$PWD\build\smoke-exe" --result-file "$PWD\build\smoke-exe-result.json"
```

自检覆盖四个服务启动、静态资源、HTTP 控制权验证、任务实际执行、范围外接口/跳转阻断、撤销与报告导出。需要先退出使用同一数据目录的应用。服务诊断日志位于应用数据目录 `api.log`、`gateway.log`、`model.log`、`worker.log`。

## 使用流程

在“我的应用”登记目标并验证授权，按需添加并验证测试账号。“开始检查”提供三步引导；高级接口导入和 AI 自动检查按需展开。“检查记录”默认展示概览与最近事件，“检查结果”默认使用易懂版报告。详细说明见 [易用性调整](docs/usability.md) 与 [固定工作库](docs/fixed-storage.md)。

## 当前实现

- 精确主机、协议、端口、路径与排除路径；本人应用 HTTP 文件 / DNS TXT 控制权验证；隔离靶场 IP 绑定；授权版本、撤销、到期与总预算。
- 每次请求独立检查授权并原子扣减预算，校验所有 DNS 结果，连接固定到已校验 IP，HTTPS 保留原主机的证书验证。不使用环境代理，不跟随跳转。
- OpenAPI / HAR / 手工 JSON 接口导入，测试账号凭证加密，GET 固定模板、身份响应摘要比较。
- 独立接口发现队列：从页面、静态 JavaScript 和 OpenAPI JSON 提取候选，按预算跟随授权内页面/模块引用；展示来源、范围与实际访问记录，手工勾选导入，未知方法与动态路径不自动执行。
- OpenAI 兼容接口与本地模型；发送预览、结构化建议校验、每次调用费用预检；模型没有网络或终端工具。
- 脱敏证据、人工证据录入、发现去重/合并/驳回/审核、中文 Markdown / HTML / ZIP 报告。第三方 SRC 目标只能整理规则和人工证据。
- 暂停、停止和全局紧急停止；后续请求被阻断，已经发出的请求继续留有处理记录。暂停后需要新建任务，避免无意重放。

### 明确限制

这是第一版固定模板实现，不是通用自动漏洞利用系统。目前模板包括 MIME / CSP / HSTS 响应配置线索、私钥格式 / 调试堆栈 / 数据库错误标记，以及身份响应摘要对比。全部命中先作为待验证线索，不保留匹配出的秘密内容。逻辑漏洞仍需提供权限矩阵、人工对照并复现；相同响应不能直接判定越权。

漏洞测试仅开放 **GET、无查询参数的已导入接口**。接口发现仅对用户提供的入口及范围内页面/静态模块引用发送 GET，每次计入总预算（单次最多 20 请求、120 秒、2 层、300 候选，每个响应最多 64KB），不执行脚本，不跟随重定向，不因 JavaScript 或接口文档提到业务 API 就自动请求。POST/PUT/PATCH/DELETE 可以登记但不能执行，没有写入审批或执行通道。参数化 OpenAPI 路径需要人工替换为合成数据实例后导入。未实现自动状态机探索、任意输入注入、自动漏洞利用或扫描器命令。

GET 也可能触发业务副作用，导入前必须确认接口为只读，并将退出登录、导出、支付等地址加入禁止路径。不要把生产账号/数据带入测试。控制权验证不能替代合法授权。

云模型只接收接口内部 ID、HTTP 方法及固定测试类型，不接收 URL、响应正文或自由业务描述；本地模型可接收脱敏后的手工描述。用户可在 AI 页将建议创建为任务，执行器重新校验接口、测试类型、账号和预算；生成建议本身不会发送测试请求。

新测试任务会在本地数据库保存脱敏 HTTP 请求头、请求体状态、响应头及文本响应体，并保留哈希、长度和截断标记。当前仅执行 GET，无请求体会明确显示“无请求体”。每条明细内容预算为 64 KiB（头信息各有 16 KiB 上限），超限截断；二进制、未解码的压缩响应和请求失败均明确标记未采集，不伪造原文。账号凭证、常见敏感字段、个人信息与私钥经脱敏后才保存，仍须使用专门账号及合成数据。旧证据未记录的正文无法补回。

HTTP 明细在任务详情中按需读取，并随任务报告导出；全局状态轮询不携带正文，云模型上下文不新增这些数据。人工素材仍须用户事先去除业务秘密。当前没有 PDF 导出、平台自动抓取或自动提交。

测试配置可选择响应基线、身份响应对比或组合模板。18 类漏洞的覆盖目录仅表示当前部分覆盖或后续规划，不会启用攻击载荷或额外网络工具；扩展约定见 `docs/test-extension.md`。

## Docker 隔离部署（可选）

需要 Docker Engine / Docker Desktop 与 Compose v2、Python 3。

```powershell
python scripts/setup_env.py
docker compose --profile demo up --build -d
```

打开 <http://127.0.0.1:8000>。在本机 `.env` 中复制 `APP_TOKEN` 填入界面；不要分享此文件。密钥仅保存在浏览器当前会话中。`ENCRYPTION_KEY` 用于账号/模型凭证加密，必须与数据库一起安全备份；丢失后无法恢复凭证。不要更换密钥后继续使用旧密文。

只有 API 发布本机端口。数据库无宿主机端口。Worker 仅接入 internal 执行网络，不能直接接入互联网、数据库或模型出口；所有测试由网关执行。API 与数据库位于 internal 控制网络，云模型使用独立出口服务。容器以非 root 身份运行，应用容器根文件系统只读。

### 演示流程

1. 登记“授权靶场”，主机 `demo`、协议 `http`、端口 `8080`、允许路径 `/`、IP `172.30.10.10`，填写隔离合成数据说明和有效期。
2. 点击“HTTP / 靶场验证”。靶场验证确认来源声明和地址绑定；不代表第三方授权审核。
3. 选择目标，在“测试任务”导入：

```json
{"requests":[
  {"method":"GET","url":"http://demo:8080/public"},
  {"method":"GET","url":"http://demo:8080/fixture/shared"},
  {"method":"GET","url":"http://demo:8080/secure/admin"}
]}
```

4. 创建两个专用账号，分别使用 `{"X-Test-Account":"reader"}` 和 `{"X-Test-Account":"admin"}`。所有 fixture 都是假数据。
5. 以至少 9 次请求预算创建任务。Worker 会执行匿名与两个账号的对比。公共页面产生的相同响应线索应判为误报；共享 fixture 是需人工对照权限矩阵的线索；`/secure/admin` 演示有权限校验的对照。
6. 查看证据，填写复现步骤并审核发现，然后导出报告。没有已确认发现时，报告不会把线索当作漏洞。

Docker 模式下，默认靶场网络仅允许 `172.30.10.0/24`，禁止网段地址、网关地址、广播地址、回环、链路本地、元数据地址和常见管理端口。自定义隔离靶场网络时，为 gateway 设置 `LAB_NETWORK_CIDRS` 并对应修改 Compose 网络配置，不要填入宿主机或公司内网网段。Docker 的本人应用类型只允许公网地址；Windows 桌面版另行提供经过 HTTP 验证的本机应用类型。

首版不开放公网第三方靶场主动测试，不能仅凭“靶场”声明把公网目标加入执行范围。公网目标必须按本人应用完成控制权验证。

## 模型配置

界面登记兼容接口，例如 `https://your-provider.example/v1`，服务端会追加 `/chat/completions`。仅在独立模型出口连接供应商。

在界面将可信云模型的完整基础地址加入云端允许地址，将可信本地模型地址加入本地允许地址（逗号分隔）并保存。未保存过设置时使用环境变量 `MODEL_CLOUD_BASE_URLS` 和 `MODEL_LOCAL_BASE_URLS`。连接可以先保存，但执行模型调用仍必须通过允许地址检查。两份名单分别约束云端/本地标记；云模型出口校验公网 DNS 并固定连接 IP，不跟随跳转、不使用环境代理。

云端调用默认关闭。在界面设置供应商所有输入/输出 token 单价的保守上界（未保存时使用 `MODEL_MAX_USD_PER_MILLION_TOKENS` 环境变量）。模型出口以输入 UTF-8 字节数、输出 token 上限及额外开销预估上界，超出调用预算即拒绝；供应商额外收费、定价变化不受本地控制，应同时设置供应商账户消费上限。单次调用无自动重试。

本地模型端点须从 model 容器可达。不要将模型接口配置为不可信服务；本地模式决定允许发送更多业务描述，不能把云端地址伪装成本地模式使用。API 密钥在数据库中加密，不返回界面。

## 本机预览与开发

不安装 Docker 也可查看界面和使用人工证据/报告功能，预览不开放网络测试或模型调用：

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r backend/requirements.txt
cd frontend
npm ci
npm run build
cd ..
python scripts/setup_env.py
.\.venv\Scripts\python scripts/preview.py
```

`setup_env.py` 不覆盖已有 `.env`，已创建时跳过该步。预览数据在 `data/preview.db`，与 Compose PostgreSQL 数据独立。前端开发可运行 `npm run dev`，由 Vite 转发 `/api` 至本机 8000。

## 验证

```powershell
.\.venv\Scripts\python -m pytest backend/tests -q
cd frontend
npm run build
```

测试覆盖 URL/路径编码边界、相似域名与子域、端口与协议、DNS 重绑定、IPv4/IPv6、私网与代理、范围外跳转、授权生命周期、请求预算、加密与脱敏、证据审核及报告、模型上下文隔离。测试不会向真实目标发送探测请求。

完整容器验收还需在安装 Docker 的主机执行上面的演示流程，并确认 Worker 无法访问外网、数据库、宿主机或其他容器。没有 Docker 时，Python 测试不能代替这项网络隔离验收。

## 主要接口

所有 `/api` 接口需要 `X-API-Key`。`/internal` 接口仅在对应 gateway/model 角色下接受独立 `X-Internal-Token`，不发布宿主机端口。

| 接口 | 功能 |
|---|---|
| `POST /api/targets`、`PUT /api/targets/{id}` | 登记 / 修改授权，修改后须重新验证 |
| `POST /api/targets/{id}/verify?method=http或dns` | 经执行网关验证控制权 / 靶场绑定 |
| `POST /api/targets/{id}/revoke` | 撤销授权与后续执行 |
| `POST /api/targets/{id}/imports`、`/accounts`、`/workflow` | 接口、专用账号、版本化业务 / SRC 规则 |
| `POST /api/jobs`、`/api/jobs/{id}/pause或stop` | 创建与控制固定模板测试 |
| `POST /api/emergency-stop` | 停止所有后续任务请求 |
| `POST /api/models`、`/api/targets/{id}/model-preview`、`/proposals` | 模型配置、发送预览与建议 |
| `POST /api/targets/{id}/proposals/run` | 将选定建议转成受控固定模板任务 |
| `POST /api/targets/{id}/manual-evidence` | 不发送网络请求的人工证据录入 |
| `PATCH /api/findings/{id}`、`POST /api/findings/{id}/merge` | 人工审核与同目标合并 |
| `GET /api/targets/{id}/report?format=md或html或zip` | 仅导出已确认发现 |

初始数据库使用建表初始化；后续改变数据库表结构前须引入显式迁移。证据数据保存在本地数据库卷，未上传第三方存储。
