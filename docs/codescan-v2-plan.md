# CodeScan v2 方案：优先级判断 + 修复建议（对标 Snyk 的两个缺口）

> 背景：v1 已经跑通（开发 → 上架 4YI → 安装 → 扫真实项目 → 出干净报告 + PDF）。
> 实战对比 Snyk 后，发现 v1 的报告是**"原始漏洞清单，需要人工研判"**，缺两块能力：
> ① **不判断漏洞是否真的会被利用**（没有可达性分析）
> ② **不替你把修复做深/做自动**（只给"升到哪个版本"，不算传递升级路径、不自动修）
>
> 本文把补齐这两块的工作**分阶段**规划，**先做简单、见效快的**。关联：[codescan-v1-plan.md](./codescan-v1-plan.md)。

---

## 一、目标与非目标

**目标**：在不推翻 v1 架构（Semgrep + Trivy 当 CLI、单服务、离线、零 token）的前提下，
逐步提升报告的**信噪比**和**可行动性**，拿到 Snyk 减噪/优先级体验的**大部分实际好处**。

**明确不追求**：短期内不重建 Snyk 的护城河（函数级可达性 + 私有漏洞情报库）。那是大工程，
需要"CVE → 漏洞函数"映射库 + 跨过程调用图，公开数据不足以支撑，留作长期探索。

---

## 二、分阶段路线图（按性价比排序）

| 阶段 | 内容 | 价值 | 成本 | 是否需决策 |
|---|---|---|---|---|
| **P1-A** | 直接依赖 vs 间接依赖 **标注** | 高（一眼知道先修哪个） | 低 | 否 |
| **P1-B** | 轻量可达性：包**在源码里是否被 import** | 高（砍掉"装了没用"的噪音） | 低–中 | 否 |
| **P2-A** | 依赖路径（"X 是被 A→B 带进来的"） | 中 | 中 | 否 |
| **P2-B** | 传递依赖的**升级路径指引**（该升哪个顶层包） | 中 | 中–高 | 否 |
| **P3-A** | 自动修复 PR（改锁文件、开 PR） | 中 | 中（外向操作，需仓库写权限） | 是 |
| **P3-B** | **AI 解释漏洞 + 建议修复**（接 4YI LLM gateway） | 最高 | 中 | **是（要不要加 LLM）** |
| **P3-C** | 完整函数级可达性 | 最高 | 极高 | —（暂不做） |

**先做 P1（A + B）**——不加 AI、不动外部系统，下一次 Release 就能带上。

---

## 三、P1 详细实现方案（先做这个）

### P1-A：直接 / 间接依赖标注

**原理**：Trivy 的 JSON 输出里，`Results[].Packages[]` 带 `Relationship`（`direct` / `indirect`）
和 `DependsOn`；漏洞项 `Vulnerabilities[]` 通过 `PkgName`/`PkgID` 关联到具体包。
把漏洞包映射回它的 `Relationship`，就知道它是**你直接声明的**还是**被别的包顺带带进来的**。

**改动点**：
- `internal/engine/trivy.go`：解析 `Results[].Packages[]`，建 `PkgID/PkgName -> Relationship` 映射；
  归一化 finding 时带上"直接/间接"。
- `internal/store`：`findings` 表加一列 `relationship TEXT`（`direct`/`indirect`/空）。
  注意：现有 `schema.sql` 是 `CREATE TABLE IF NOT EXISTS`，**加列要写一次性 migration**
  （`ALTER TABLE findings ADD COLUMN relationship TEXT`，用 pragma 判断列是否已存在再加，保证幂等 + 不丢老数据）。
- UI（`web/templates/scan.html`）+ PDF（`internal/api/pdf.go`）：在每条 SCA finding 上显示
  "直接 / 间接" 标签；过滤器里可加"只看直接依赖"。

**验收**：扫 bieases-shop，SCA findings 能正确区分直接/间接（对照 package.json 里声明的即为直接）。

### P1-B：轻量可达性（源码是否 import 了该包）

**原理**：对**直接依赖**的漏洞包，去源码里查它到底有没有被引用。不做函数级，只做"包级"：
- npm/TS：`require('pkg')`、`import ... from 'pkg'`、`import 'pkg'`
- Python：`import pkg` / `from pkg import ...`
- Go：import 路径包含该 module
- Java：`import <group.pkg>...`（较粗，可选）

在锁文件里**存在**、但源码里**从未被 import** 的直接依赖 → 标记为"疑似未使用"，**降低优先级**。

**说明 / 边界**：
- 只对**直接依赖**有意义。**间接依赖天然不会被直接 import**，所以对间接依赖不下"未使用"结论
  （避免误判），间接依赖的优先级交给 P1-A 的"间接"标签处理。
- 这是**包级**近似，不是 Snyk 的函数级可达性；会有边角误差（动态 require、别名导入等），
  所以措辞用"疑似未使用 / 可能未用到"，**只降优先级、不直接隐藏**。

**改动点**：
- 新增 `internal/reach`（或放 engine）：给定源码目录 + 包名列表，用 Semgrep 规则或带 host 白名单的
  grep 扫 import，返回"被引用的包集合"。（优先用 Semgrep，语言感知更准。）
- runner 在归一化后、写库前，对直接依赖的 SCA finding 打上 `used` / `unused_suspected`。
- `findings` 表加一列 `usage TEXT`（同样走幂等 migration）。
- UI/PDF 展示 + 过滤（"隐藏疑似未使用"）。

**验收**：构造一个装了但没 import 的直接依赖 → 被标"疑似未使用"；真正 import 的 → 标"已使用"。

### P1 完成后的效果
报告从"一长串漏洞"变成"**能按 直接/间接 + 是否使用 排优先级**"——把"你自己装的、且真用到的"高危顶到最前面。
这就拿到了 Snyk 减噪体验的**大部分实际价值**，且**不加 AI、不外传代码**。

---

## 四、P2 / P3 概要（后续）

- **P2-A 依赖路径**：解析 Trivy 的 `DependsOn` 依赖树，展示"A→B→漏洞包"，让人知道从哪下手。
- **P2-B 升级路径**：对间接依赖，算"升哪个顶层包能带入修复版本"。npm 相对好做，Java/Maven 较难。
- **P3-A 自动修复 PR**：生成分支、更新锁文件、开 PR。**需要仓库写权限 + 跑包管理器**，是外向操作，要人确认。
- **P3-B AI 解释 + 修复建议** ⭐：接 4YI 平台 LLM gateway，对每条漏洞给"风险解释 + 结合代码的修复建议"。
  **价值最高**，但**打破 v1"零 LLM、零 token"设计**——`4yi-app.json` 要加 `models` 槽位，计费模型改变。
  4YI 本是 AI 市场，接上反而更契合。**是否做取决于产品决策（要不要加 AI）。**
- **P3-C 函数级可达性**：需 CVE→漏洞函数库 + 调用图，暂不做。可长期关注 Semgrep Pro + OSV 的函数级数据。

---

## 五、待决策项

1. **P3-B 要不要加 AI？** 这是 v2 最出彩、也最"像 Snyk 帮你判断+修"的能力，但要引入 LLM。
   —— 需与平台侧确认「非 token 计费如何配 models 槽位」，并由你拍板是否偏离"零 token"定位。
2. **Java 后端 SCA 深度**：当前 `--offline-scan` 下 Java 传递依赖覆盖浅。若要补全，需在**构建/CI 环节**
   预热 Maven `.m2` 缓存后再扫，属于流程改造。

---

## 六、里程碑（v2）

- [ ] **M1（先做）** P1-A 直接/间接标注：trivy 解析 Relationship + findings 加列(幂等 migration) + UI/PDF 展示与过滤
- [ ] **M2（先做）** P1-B import 可达性：reach 模块 + 直接依赖标 used/unused + UI/PDF 展示与过滤
- [ ] M3 P2-A 依赖路径展示
- [ ] M4 P2-B 传递依赖升级路径（npm 优先）
- [ ] M5 P3-A 自动修复 PR（需仓库写权限，人工确认）
- [ ] M6 P3-B AI 解释+修复（**待决策**：是否加 LLM / 平台侧计费确认）

> 下一步：从 **M1（直接/间接标注）** 开始——成本最低、立刻提升优先级判断，且不需要加 AI。
