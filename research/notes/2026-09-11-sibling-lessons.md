# 从兄弟构建选择性学习（2026-09-11）

来源：`mega-index-map` **v0.3.3**（DSH-only 的窄版插件；本仓是通用+延伸版）。读取方式：**只读**，
路径由 `.isolation.local.json` 本地声明（不随包发布），`tools/check-isolation.mjs` 守护这条纪律。

## 一、采纳了什么（都做了 kohane 原生改写，不照抄）

| 采纳项 | 落点 | 说明 |
|---|---|---|
| **`library_sessions`**（第 14 把工具） | `lib/core.mjs` | 6 个 op：`list` / `read` / `tail` / `search` / `record` / `status`；按压缩帧魔数逐帧解码；支持导出的 ZIP 归档与 `<zip>#<member>`；`content:true` 才给正文；**每个响应都带时区**；撕裂尾帧只计数不臆测；运行时无解码器时明说而不是报「空历史」 |
| **不变量检查族** | `tools/check-*.mjs` | `check-unicode` / `check-consistency` / `check-portability` / `check-isolation`，依赖为零、可离线跑 |
| **隔离纪律的机器化** | `tools/check-isolation.mjs` + `.isolation.local.json` | 兄弟构建由**本地声明**（环境变量或本地文件），**发布文件里一个机器路径都不许出现**；另带 `snapshot` / `verify` 见证（哈希本仓 + 兄弟树 + 库索引），可证明「跑测试没动过任何东西」 |
| **npm 脚本与验证章节** | `package.json` / `README.md` | `npm run check` / `selfcheck` / `verify`；README 增「Verification」章节 |

## 二、按 kohane 自己的规矩做的适配（不是照抄的地方）

1. **临时文件规则相反**：兄弟版要求「临时文件用 `os.tmpdir()`」；kohane 的现行纪律是**不许把临时文件落到系统盘**。
   → kohane 的 `check-portability` 反过来：**创建**临时目录若走 `os.tmpdir()` 即判为问题，要求落在 `<DSH_HOME>` 之下。
2. **ASCII 口径收窄**：只约束**发布包**（`lib/` `mcp/` `cli/` `README.md` `LICENSE` `package.json`），
   汉字例外只留 `SENSITIVE_PATTERNS`（功能性）；**语言中立的排版符号**（破折号/箭头/省略号/弯引号）允许；
   `research/`、`tools/`、`TODO.md`、`workstation/` 是工作文档，**明确不在范围内**（研究笔记本来就是中文）。
3. **自证式断言**：`check-consistency` 校验 README 与 `TOOLS` 注册表、schema 的 op 列表与分派里的 `allowed:` 列表、
   README 里引用的数字与实时表（如签名数 109）是否一致，并核对本包对自己的安全声明（无网络 API、库不打印、无悬挂标记）。
4. **两处误报的教训**：检查规则一开始把「候选工具目录里列举的典型安装路径」和「文档里举例的路径」当成硬编码；
   **检查器要编码真实意图**，否则噪音会淹没信号（已按此收窄，并在脚本头部写明例外理由）。

## 三、实测

| 项 | 值 |
|---|---|
| 工具数 | **14**（MCP `tools/list` 实测一致） |
| `selfcheck` | **183/183 全绿**（新增「会话存储读取」一节：多帧 zstd + 纯 JSONL + ZIP 归档，全部用临时夹具） |
| 四道不变量检查 | 全部 OK（ascii / consistency / portability / isolation） |
| 真实会话库 | `library_sessions status` → **267 个会话 / 587 MB**；`list` 从头部读出 id/cwd/preset 与标题；某 139 帧文件里**1 帧撕裂**并被如实计数 |

## 四、有意不采纳（选择性的另一半）

| 未采纳 | 理由 |
|---|---|
| 兄弟版的 `library_index` 扩展 op（`audit` / `index` / `verify` / `review` / `prune`） | 是一个有状态的大特性（目录对账、指纹核对、敏感复审、清理），值得单独一轮，不宜夹带 |
| `library_sessions bootstrap`（首装整库淘洗） | 它服务于兄弟版的注入/提示生命周期（DSH host 侧）；kohane 没有注入面，硬搬只会多一个没人触发的状态机 |
| `bench.mjs` + `baseline.json` | 需要在一台安静机器上先测出可信基线，否则阈值就是编的 |
| `.github/workflows/publish.yml` | 本仓尚无远端仓库可跑；等发布环节（TODO P3）真正开始时再落 |

## 五、踩坑记录

- **不要把内联 `node -e` 交给 PowerShell**（嵌套引号会被吃掉，本轮因此摔了三次）：写临时 `.mjs` 再跑。
- 拼接大段代码进 `core.mjs` 时，锚点要**唯一且完整**：本轮两次因为锚点吞掉相邻对象的 `{` 或 `required` 而语法错误，
  已改为「先备份 → 拼接 → `node --check` → 失败即回滚」的固定流程。
