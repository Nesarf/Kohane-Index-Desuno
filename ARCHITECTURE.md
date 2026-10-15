# KID 架构

> 本文回答三件事：**东西在哪**（模块地图）、**数据怎么流**（层与落盘）、**凭什么信它**（不变量）。
> 读者假定是接手这个仓库的人，而不是第一次听说它的人。

---

## 1. 模块地图

```
kohane-index-desuno/          交付包（唯一发布物）
├─ lib/core.mjs               引擎核心：单文件、纯 Node、无框架依赖
├─ mcp/index.mjs              MCP stdio 服务（把 TOOLS 暴露成 MCP 工具）
├─ cli/index.mjs              命令行（同一套 execute）
├─ README.md                  对外说明（工具清单与 op 契约）
└─ package.json               入口与 scripts

tools/                        检查器族（不发布）
├─ check-unicode.mjs          编码正确性
├─ check-consistency.mjs      文档/分派/op 面/安全声明一致
├─ check-portability.mjs      平台分支对称
├─ check-isolation.mjs        交付包与邻居、厂商名隔离
├─ check-contract.mjs         工具契约（键集、op 面、拒绝行为）
├─ selfcheck.mjs              端到端回归（256 断言）
├─ reference-check.mjs        对兄弟项目的只读差异核对（永不写回）
└─ .isolation-manifest.json   隔离基线哈希

workstation/                  WinUI 3 桌面壳
├─ src/KohaneStation/         壳（XAML + C#）
├─ engine-bridge/server.mjs   本地 HTTP 桥（复用 TOOLS，默认隔离库）
├─ tools/make-assets.ps1      从立绘生成头像/图标/表情
└─ build.ps1                  可复现构建

research/                     证据与设计（可提交，但不随包发布）
├─ notes/                     设计稿与调研（含 KPB 设计稿）
└─ fl-studio/                 格式逆向、样本、工具
```

**为什么核心是单文件**：跨 harness 复用时，「一个文件 + 零依赖」是最省事的形态；
代价是文件大（350 KB 级），所以约束靠不变量与自检来守，而不是靠目录结构。

---

## 2. 引擎分层（自上而下调用）

```
工具层 TOOLS[]               16 个工具的 name/description/inputSchema/execute
   ↑
分析层 analyzers             内置（Unity/Blender/原生容器）+ 本地 analyzer-add（外部命令 + argv 模板）
   ↑
探测层 content probes        魔数表之后、文本启发之前的「内容探针」（.map 色带 / .vfpatch / .mms …）
   ↑
签名层 FILE_SIGNATURES       109 条魔数签名 + 文本扩展名表 + ZIP 包内格式
   ↑
文件与系统层                 fs / path / os / child_process / crypto / zlib / worker_threads
```

**判定顺序是契约**：魔数优先于扩展名（扩展名可伪造），内容探针优先于「看起来像文本」，
本地 analyzer 只能**扩展**覆盖面、永不**遮蔽**内置。

---

## 3. 数据落盘

一切状态在 `$DSH_HOME`（默认 `~/.dsh`）之下：

| 文件 | 内容 |
|---|---|
| `library/index.json` | 对象库：记录（含加密体 `__content` 与复审标记 `review`） |
| `library/log.jsonl` | **append-only** 日志：谁在何时改了/判了什么 |
| `library/plugins.local.json` | 能力挂接（本地层，不发布） |
| `library/formats.local.json` | 本地格式包（用户教的签名/扩展名/分析器） |
| `sessions/` | 本机 harness 会话（每记录一个压缩帧） |

**两条纪律**：新建对象的正文**只经由加密体**（敏感对象）或明文体（普通对象），不存在「半加密」；
任何派生缓存都可重建，不与事实源争抢权威。

---

## 4. 跨 harness 表面

```
               ┌──────────────── TOOLS[]（同一套 execute） ────────────────┐
宿主插件 ──────┤                                                          ├──────  CLI
MCP 客户端 ────┤   签名 → 探针 → 分析器 → 库/索引 → 加密 → 会话 → 能力目录   ├──────  MCP stdio
桌面壳 ────────┤                                                          ├──────  本地 HTTP 桥
               └──────────────────────────────────────────────────────────┘
```

桥只做三件事：`GET /tools/list`、`POST /tools/call`、以及**库归属**的显式声明
（默认把库隔离在 `workstation/data`，要共用机器级库必须显式开口）。

---

## 5. 关键机制

### 5.1 两层能力模型
- **能力层**（随包发布）：`Kohane Bassline` + 功能词。结果里不出现厂商名。
- **本地挂接层**（不发布）：本机哪个插件提供哪个能力；只在 `op=provenance` 时显示。
- 好处：包的输出**不随机器变化**，而机器差异被收进一张本地表。

### 5.2 索引对账
`rebuild / status / audit / index / verify / review / prune` 七个 op 各管一件事：
去重与排序、现状、**双向对账**（盘上有而库里没有 / 库里有而盘上没了）、批量登记、
**身份校验**（指纹）、加密体复审、清理派生行。
其中一条硬规则：**地址不是路径**（`scheme://`、`host:port` 不当文件系统路径处理）。

### 5.3 工作区状态（VCS）
一次 git 调用覆盖整个仓库：`status --porcelain=v2 -z` 同时给出暂存与工作区状态，
`numstat` 给每侧 +/- 行数；结果按仓库缓存 2 秒。
对外给出**编辑器式装饰**：字母、两套字母（index/worktree）、颜色、改名来源、冲突与子模块标记、
目录向上折叠。没有 git、或路径不在仓库里，**如实回报**而不是报错。

### 5.4 音频与并行
- 波形：WAV/AIFF 的 min/max 包络（PCM 8/16/24/32 与 float32；AIFF 含 80-bit 扩展采样率）。
- 并行：**常驻 worker 池**。教训写在代码注释里——**每次调用现开 worker 会输给 for 循环**
  （实测 0.36x），常驻复用后才翻正（1.34x）；低于阈值一律单核，因为「比循环慢的池子不如没有」。

### 5.5 加密与复审
HKDF 派生 + AES-256-GCM。敏感对象封存；**复审**是显式的：`clear`（放行并记录理由）或
`revoke`（维持封存并记录判断）。已封存的对象也能被复审——否则最需要判断的那批永远无人判断。

---

## 6. 不变量各证明什么

| 检查 | 证明 | 反例（它要拦住的东西） |
|---|---|---|
| unicode | 交付文本没坏 | 解码损失留下的替换字符、孤立代理项 |
| consistency | 说法与做法一致 | 文档列了没注册的工具、op 说了不做 |
| portability | 不是只在一种平台上能跑 | 只写 win32 分支 |
| isolation | 包是自洽的 | 引用兄弟项目、把厂商名带进结果 |
| contract | 工具名副其实 | 未知 op 照做、键集敞开、探针不应答 |
| selfcheck | 行为没退步 | 语义回归（256 项断言） |

**为什么这么多种检查而不是一个大的**：每一种失败模式对应一种读法，坏了能一眼看出坏在哪一类。

---

## 7. 路线

| 阶段 | 内容 | 状态 |
|---|---|---|
| 本体 | 16 工具、五道检查、自检、顶层文档 | **进行中**（本文即其中一件） |
| 发布 | 元数据、`CHANGELOG`、干净机器安装、CI | 待做 |
| 界面 | 工作站余下观感、状态能力的界面深化 | 待做 |
| **KPB** | 作编混作为**封存式 DLC**：`.kbb/.kbi/.kba/.kbs/.kbm/.kbw/.kbv`，体积窗口 800 MB–2 GB，离开 KID 打不开 | 设计稿已成，实现待排 |

KPB 的两条硬约束（体积窗口、束内无第三方容器）与逆向范围，见
`research/notes/2026-10-15-kpb-design.md`。
