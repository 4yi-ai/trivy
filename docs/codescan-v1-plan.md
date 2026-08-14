# CodeScan v1 方案（Semgrep + Trivy，上架 4YI Marketplace）

> 目标：做一个类 Snyk 的静态代码扫描应用，把 **Semgrep（SAST）** 和 **Trivy（SCA/镜像/IaC/密钥/License）**
> 两个 CLI 工具套一层 Web 界面，打成**同一个仓库、同一个 app**，发布到 4YI marketplace。
> 本文只定义 **v1 范围**，先写清楚再开工。命名 `codescan` 为工作名，可改。

关联文档：[4yi-marketplace-deployment-guide.md](./4yi-marketplace-deployment-guide.md)（上架流程 & 踩坑清单，方案严格遵循）。

---

## 一、v1 范围（做什么 / 不做什么）

**做：**
- 三种扫描来源：① 公开 Git 仓库 URL ② 上传 zip/tar 代码包 ③ 容器镜像 tag
- 私有 Git 仓库：**用完即弃 token**（界面填一次 → clone → 用完丢弃，不落库）
- 引擎：Semgrep + Trivy，输出统一归一化成 findings 存 SQLite
- Web 界面：发起扫描、任务列表、结果详情（按 severity/文件/规则分组）、导出 SARIF/JSON
- 异步执行：请求建 job 立即返回，后台串行扫描，前端轮询进度
- 单公开服务 + 持久卷 SQLite，契合 4YI 1.5C / 4–6G

**不做（留 v2+）：**
- GitHub/GitLab OAuth / GitHub App「登录即扫私有库」
- Token 加密持久化（「记住我的仓库」）
- 多 worker / postgres / 队列中间件
- LLM 辅助（AI 解释漏洞 / 建议修复）—— 见「六、marketplace 契合度」
- 定时扫描、Webhook、PR 集成、diff 增量扫描

---

## 二、两个引擎的能力边界

| 引擎 | 类别 | 扫什么 | 命令（v1） |
|---|---|---|---|
| **Semgrep** | SAST | 代码逻辑漏洞：注入、XSS、路径穿越、SSRF、弱加密、硬编码等；多语言 | `semgrep scan --config <ruleset> --json --output out.json <dir>` |
| **Trivy** | SCA | 依赖库 CVE（go.mod/package.json/requirements.txt/pom.xml…） | `trivy fs --scanners vuln --format json <dir>` |
| **Trivy** | Secret | 硬编码密钥/token | `--scanners secret` |
| **Trivy** | IaC | Terraform/K8s/Dockerfile/Helm 配置错误 | `--scanners misconfig` |
| **Trivy** | License | 依赖开源协议 | `--scanners license` |
| **Trivy** | Image | 容器镜像 OS 包 + 应用依赖 CVE | `trivy image --format json <image>` |

- 代码类扫描（来源 ①②）：同一个工作目录先跑 Semgrep，再跑 `trivy fs`（一次带上 vuln,secret,misconfig,license 多 scanner）。
- 镜像扫描（来源 ③）：只跑 `trivy image`，不跑 Semgrep。
- **Semgrep 规则集**：v1 用**内置/vendored 规则**（如 `p/default`、`p/security-audit`、`p/secrets`），
  **不依赖 `--config auto`** 的 registry 在线拉取，避免 4YI pod 出网受限或需登录导致扫描失败。
  规则随镜像打包，离线可用。

---

## 三、架构（方案 A：单服务 + SQLite）

```
┌─────────────────────── 4YI EKS Pod (unprivileged, 1.5C / 4-6G) ───────────────────────┐
│  codescan (Go, 单公开服务, 监听 0.0.0.0:8080, 容器内纯 HTTP)                             │
│  ┌────────────┐   ┌──────────────┐   ┌──────────────────────────────┐                   │
│  │ HTTP API   │──▶│ 内存任务队列  │──▶│ 后台 worker (goroutine, 并发=1) │                 │
│  │ + 静态前端  │   │ (bounded)    │   │  clone/unzip → semgrep → trivy │                 │
│  └────────────┘   └──────────────┘   │  → 解析 → 写 SQLite → 清理工作目录 │               │
│         │                            └──────────────────────────────┘                   │
│         ▼                                                                                │
│  持久卷 /app/data:  scan.db (SQLite)  |  trivy-cache/  |  jobs/<id>/(临时, 扫完删)         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

- **技术栈**：Go（`net/http` 或 chi）。前端 v1 用服务端模板 + 少量 JS/htmx 做轮询（最轻，单二进制 `go:embed` 打包）；
  也可换成小型 React build 嵌入，但 v1 不必要。
- **为什么单服务**：1.5 CPU 很紧，多服务互抢 CPU；扫描本身串行，进程内后台 goroutine 足够。
- **为什么 SQLite 不用 Postgres**：省一个服务、省 CPU/内存；结果数据是单租户实例内自用，SQLite 挂持久卷够用。

---

## 四、数据模型（SQLite）

```sql
-- 扫描任务
CREATE TABLE jobs (
  id          TEXT PRIMARY KEY,          -- uuid
  source_type TEXT NOT NULL,             -- git | zip | image
  source_ref  TEXT NOT NULL,             -- repo url / 原始文件名 / image tag（脱敏，不含 token）
  status      TEXT NOT NULL,             -- queued|fetching|scanning|done|failed|canceled
  progress    TEXT,                      -- 人类可读的当前阶段
  error       TEXT,                      -- 失败原因
  summary     TEXT,                      -- JSON: {critical,high,medium,low,info} 计数
  created_at  INTEGER NOT NULL,
  started_at  INTEGER,
  finished_at INTEGER
);

-- 归一化后的发现项
CREATE TABLE findings (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id    TEXT NOT NULL REFERENCES jobs(id),
  tool      TEXT NOT NULL,               -- semgrep | trivy
  category  TEXT NOT NULL,               -- sast | sca | secret | iac | license | image
  severity  TEXT NOT NULL,               -- critical|high|medium|low|info
  rule_id   TEXT,                        -- semgrep rule / trivy CVE / check id
  title     TEXT,
  message   TEXT,
  file_path TEXT,
  line      INTEGER,
  pkg_name  TEXT,                        -- SCA/image: 受影响包
  pkg_ver   TEXT,
  fixed_ver TEXT,                        -- 可升级到的修复版本
  cve       TEXT,
  raw       TEXT                         -- 原始 JSON 片段，便于导出/追溯
);
CREATE INDEX idx_findings_job ON findings(job_id);
```

> 时间戳用 Unix 秒。若多用户共用一个实例、需要按用户隔离，v1 可加 `owner` 字段；4YI 是按组织安装，
> 天然组织级隔离，用户级隔离按需再加。

---

## 五、HTTP 接口 & 页面

**API：**
| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/healthz` | 健康检查：无认证、不扫描、不迁移、快速 200（部署指南第六节硬要求） |
| POST | `/api/scans` | 建 job：body 含 source_type + ref（+ 私有库可选 token） → 立即返回 job id（**异步**） |
| GET | `/api/scans` | 任务列表 |
| GET | `/api/scans/{id}` | 任务详情 + summary + 进度（前端轮询这个） |
| GET | `/api/scans/{id}/findings` | 发现项列表，支持 severity/category/file 过滤 |
| GET | `/api/scans/{id}/export?format=sarif\|json` | 导出 |
| POST | `/api/scans/{id}/cancel` | 取消排队/进行中的任务 |

**页面（服务端模板）：**
- `/` 新建扫描（选来源 + 填 URL/传文件/填镜像；私有库展开 token 输入框，提示「仅本次使用、不保存」）
- `/scans` 任务列表（状态、summary 徽章、时间）
- `/scans/{id}` 结果详情（severity 分组、文件树、规则说明、导出按钮）

**关键：POST /api/scans 绝不同步跑扫描**——只落 job + 入队 + 立即返回，否则大仓库/冷启动必然超过 4YI 网关超时 → 502。

---

## 六、异步执行 & 资源护栏（4–6G / 1.5C 的命门）

后台单 worker 处理流程，每个 job：
1. 建工作目录 `/app/data/jobs/<id>/`
2. 取源：
   - git：`git clone --depth 1 --single-branch <url>`（私有：URL 注入 token；clone 后立刻从内存丢 token）
   - zip：解压，**防 zip-slip**（拒绝 `../` 路径穿越）
   - image：跳过，直接 `trivy image`
3. **护栏**（防 OOM / 撑爆磁盘）：
   - **并发 = 1**（串行扫描，避免 Semgrep + Trivy 内存叠加）
   - **单任务超时**（如 15 min，`context.WithTimeout`，超时 kill 子进程）
   - **仓库/解压体积上限**（如 clone 后 `du` > 1–2 GB 直接拒绝）
   - `semgrep --max-memory 2048`、`--timeout` 限制；跳过 vendor/node_modules 等目录
   - **Trivy DB 缓存到持久卷**：`TRIVY_CACHE_DIR=/app/data/trivy-cache`，避免每次重下几百 MB
4. 跑引擎 → 解析 JSON → 归一化写 findings + 更新 job summary/status
5. **清理**：删 `/app/data/jobs/<id>/`（结果已在 DB，工作目录不留），token 不落任何地方

**启动预热**：`trivy` 漏洞库首次要下载，**放后台 goroutine 异步预热，绝不阻塞 `/healthz`**（否则冷启动健康检查超时 → 502，重蹈 PentAGI 覆辙）。

**内存预算**：Semgrep 大仓库可吃 1–2G，Trivy 扫描期 DB 常驻 ~1G；串行执行 + 体积上限 + `--max-memory`
保证峰值落在 4–6G 内。建议 app 资源配 **cpu 1.5 / memoryMb 6144**。

---

## 七、marketplace 契合度（要不要加 AI）

4YI 是 **AI Marketplace**。纯扫描器没有 AI 触点，可能显得不「AI」。v1 先不做，但**预留**一个后续增强点：
- v2 加一个可选的「AI 解释这条漏洞 / 建议修复」按钮，走 4YI gateway LLM，届时在 `4yi-app.json` 加 `models` 槽位。
- v1 的 `4yi-app.json` **不含 `models`**（安装时就不会出现模型下拉框，符合预期）。
- 若上架时平台要求必须是 AI 应用，再把这个 AI 触点提前到 v1。**这一点需要跟平台侧确认。**

---

## 八、仓库交付物 & 目录结构

```
codescan/
├── 4yi-app.json            # 单 public 服务声明（见下）
├── Dockerfile              # 多阶段：build Go 二进制 → 运行镜像含 semgrep+trivy+git
├── go.mod / go.sum
├── cmd/codescan/main.go    # 入口：起 HTTP + 后台 worker
├── internal/
│   ├── api/                # handlers、路由、/healthz
│   ├── scan/               # 队列、worker、护栏
│   ├── engine/             # semgrep.go / trivy.go：调 CLI + 解析 JSON + 归一化
│   ├── store/              # SQLite（migrations、queries）
│   └── source/             # git clone / unzip / image ref 处理
├── web/                    # 模板 + 静态资源（go:embed）
└── rules/                  # vendored semgrep 规则（离线）
```

**`4yi-app.json`（v1）：**
```json
{
  "version": 1,
  "services": [
    {
      "name": "web",
      "type": "web",
      "imageSource": "build",
      "dockerfile": "Dockerfile",
      "context": ".",
      "route": "public",
      "port": 8080,
      "healthPath": "/healthz",
      "env": {
        "HOST": "0.0.0.0",
        "PORT": "8080",
        "DATA_DIR": "/app/data",
        "TRIVY_CACHE_DIR": "/app/data/trivy-cache"
      },
      "storage": { "sizeGb": 10, "mountPath": "/app/data", "fsGroup": 10001 },
      "resources": { "cpu": 1.5, "memoryMb": 6144 }
    }
  ]
}
```

**Dockerfile 要点：**
- 多阶段：`golang:1.23` 编译 → 运行镜像 `python:3.12-slim`（Semgrep 是 Python）
- 运行镜像装：`pip install semgrep`、下载 `trivy` release 二进制、`apt-get install git ca-certificates`
- 跑非 root 用户，UID/GID 与 `fsGroup: 10001` 对齐（否则写持久卷权限失败）
- vendored 规则 COPY 进 `/app/rules`
- 注意：镜像会偏大（Semgrep 依赖多），可接受；如需瘦身 v2 再优化

---

## 九、安全注意点

- **SSRF**：git URL / image ref 校验白名单 host（github.com / gitlab.com / 指定 registry），禁止内网地址、`file://`、非常规端口
- **Token**：仅内存、用完即弃、不写日志不写 DB；错误信息里也要脱敏（`source_ref` 存脱 token 的 URL）
- **zip-slip**：解压严格校验路径不越界
- **命令注入**：所有 CLI 参数用 `exec.Command` 传参数数组，绝不拼 shell 字符串
- **资源耗尽**：体积/超时/并发护栏（见第六节）
- **租户隔离**：4YI 按组织安装天然隔离；DB 查询仍按需加 owner 过滤

---

## 十、上架流程（遵循部署指南第八节）

1. 新建独立仓库（public github.com，4YI importer 只收 public github）+ 分支 `4yi-marketplace`
2. 提交 `4yi-app.json` + Dockerfile + `/healthz` + 代码
3. 本地先验证：`docker build -f Dockerfile .` 能过；容器内起服务、`/healthz` 返回 200；跑通一次 zip 扫描
4. AI Marketplace Import → Dedicated app → Create → Run Analyze
5. 核对 Proposal：单 public 服务、port 8080、healthPath、storage `/app/data` + fsGroup、resources 1.5C/6G、blockers=0
6. 配 Secrets（v1 基本无敏感配置，token 是运行期用户输入，不进 Secrets）
7. Apply → Release（指定 commit）→ Publish Gate → Publish
8. 测试组织安装 → 验证：**建任务 → 暂停/恢复或重部署 → 结果仍在**（持久化验收）

**Apply 前人工核对**（对照指南第九节）：single public ✅ / healthz 快返回 ✅ / 所有写目录落持久卷 ✅ /
首请求不同步跑重活 ✅ / PVC 权限匹配 fsGroup ✅ / 无 secret 进仓库 ✅。

---

## 十一、里程碑（v1 任务拆解）

- [ ] M0 项目骨架：Go 模块、`cmd/codescan`、`/healthz`、SQLite migration、`go:embed` 静态、Dockerfile 能 build
- [ ] M1 异步核心：任务表 + 内存队列 + 单 worker + job 状态机 + 轮询接口
- [ ] M2 来源接入：zip 上传 → 公开 git clone → 镜像 ref（含护栏：体积/超时/清理）
- [ ] M3 引擎接入：Semgrep + Trivy 调用 + JSON 解析 + 归一化写 findings + summary
- [ ] M4 界面：新建扫描 / 任务列表 / 结果详情 / 导出 SARIF·JSON；私有库用完即弃 token
- [ ] M5 4YI 适配 & 上架：`4yi-app.json`、Trivy 缓存/预热、持久化验收、Import→Publish
- [ ] M6 联调：真实组织安装 + 暂停恢复 + 重部署数据持久化验收

---

## 已定稿的决策（2026-08-10）

1. **仓库**：`github.com/4yi-ai/trivy`（public，跟 pentagi fork 同组织）。
2. **前端**：服务端模板 + htmx，`go:embed` 单二进制。**不做 SPA。**
3. **AI 触点**：**A — v1 不接任何 LLM，全程零 token。** 计费只算计算/托管（非 token 计费），
   `4yi-app.json` 不带 `models` 槽位，安装不选模型。AI 解释/修复留 v2 可选功能，骨架里预留接口位。
   待办：跟平台侧确认「非 AI 应用能否上架 + 非 token 计费怎么配」——不挡开发。
4. **镜像扫描（来源③）**：**延后**。v1 只做 ①公开 Git URL + ②上传 zip。
