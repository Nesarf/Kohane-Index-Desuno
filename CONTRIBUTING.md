# 参与开发（CONTRIBUTING）

本仓库是**工作区**：交付包在 `kohane-index-desuno/`，检查器在 `tools/`，桌面壳在 `workstation/`，
研究笔记在 `research/`。改动前先读 `README.md` 与 `ARCHITECTURE.md`。

---

## 1. 提交前必须跑的

```bash
cd kohane-index-desuno
npm run verify      # = npm run check（五道不变量）+ npm run selfcheck（端到端）
```

任何一道不过都不要提交。这五道各有分工，别把它们当重复劳动：

| 检查 | 它拦什么 |
|---|---|
| `check-unicode` | 文本坏了：替换字符、孤立代理项、BOM、杂控制字符、回车 |
| `check-consistency` | 说法与做法不一致：文档列了没注册的工具、op 说了不做、库里有网络调用或调试输出 |
| `check-portability` | 只写了一边的平台分支 |
| `check-isolation` | 交付包引用了兄弟项目、把厂商名带进输出 |
| `check-contract` | 工具名不副实：键集敞开、未知 op 照做、只读探针不应答 |
| `selfcheck` | 行为回归（256 项断言） |

**新增工具时**：清单（README 的工具行与计数）、`TOOL_INPUT_SCHEMAS`、CLI 头的工具列表、
以及 `check-contract` 的探针表，四处都要跟上；少一处检查会替你说出来。

## 2. 代码约定

- **交付的代码用英文标识**（变量、函数、注释、错误信息）：包要跨宿主复用，英文名不随语言变。
- **研究笔记与设计稿可以用中文**：它们是给人读的，不是产品的声音。
- **交付输出里不出现第三方产品名**：能力用自有词表命名，本机差异只进本地挂接表。
- **不做网络 I/O**：`check-consistency` 会静态检查；需要联网的能力一律不做。
- **库保持安静**：库内不得 `console.log`；错误通过返回值表达。

## 3. 纪律

- **磁盘**：下载 / 缓存 / 临时文件一律 `E:\DaShaoHuo\{downloads,cache,cache\tmp}`，不落 C 盘。
  中间产物用完即清。
- **路径用时再解析**：本机的 D:/F:/G: 是虚拟分区，盘符会在会话之间变化；不要把绝对路径记进下一步。
- **写前看 mtime**：本仓库可能被并发编辑，改文件前先看修改时间，改完留备份。
- **临时脚本落文件**：在 PowerShell 里内联 `node -e` 极易被引号撕裂，写成 `.mjs` 再跑。
- **兄弟项目只读**：`E:\mega-index-map` 是参考源，只读、可用于校对，**永不写回**。

## 4. 隔离

`.isolation.local.json` 声明本机特有的外部路径；`check-isolation` 用它做静态守卫。
新增外部引用请改这个文件，而不是在代码里写死。

## 5. 提交信息

一句话说清「改了什么、为什么」。修 bug 时把**症状**写进正文（例如「未知 op 照做」而非「修了 dispatch」），
因为日后检索靠的是症状。
