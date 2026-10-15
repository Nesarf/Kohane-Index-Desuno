# kohane-index-desuno（KID）

> 一台**跨 harness 的文件与知识索引引擎**：把「这是什么文件」「这台机器有什么能力」「以前记过什么」
> 收进同一个库，让任何宿主（本机 harness、MCP 客户端、命令行、桌面壳）都问同一套逻辑。
>
> 核心是**纯 Node**（无框架依赖），因此它能被任何宿主复用；外壳与它之间只经由一层很薄的本地桥。

本仓库是**工作区**，不是一个包。交付的包在 `kohane-index-desuno/`；壳、工具与研究笔记各在其位。

---

## 1. 目录地图

| 路径 | 角色 |
|---|---|
| `kohane-index-desuno/` | **交付包**：引擎核心 + MCP 服务 + CLI（唯一要发布的东西） |
| `tools/` | **检查器族**：不变量与契约的自动化核对（不随包发布） |
| `workstation/` | **WinUI 桌面壳**（集成工作站），经本地 HTTP 桥接使用引擎 |
| `the local evidence area/` (local, not published) | **证据与研究笔记**：格式逆向、宿主调研、设计稿（含厂商名，是证据链） |
| `kohane!!!/` | **persona 美术**：立绘与表情素材 |
| the local task list (not published) | 待办与当前基线 |
| `.isolation.local.json` | 与兄弟项目（只读参考源）的隔离声明 |

## 2. 三件产品

| # | 产品 | 形态 | 现状 |
|---|---|---|---|
| ① | **通用插件** | 引擎作为宿主插件/MCP 服务，供任意 harness 调用 | **已成型**：16 工具，MCP stdio + CLI 双入口 |
| ② | **DIY 索引平台** | 自己的索引/图鉴工作台（可封装、可编排） | **已并入工作站右栏**（图鉴 + 能力目录双视图） |
| ③ | **即刻文件分析** | 拖入即读的即时分析（DiskInfo 式信息密度） | **已并入工作站左栏**（状态框 + 两栏属性表） |

②③ 按最初规划合并为一个桌面工作站 `workstation/`：**编译可复现、窗口已验证、读→录→查闭环有照片为证**。

## 3. 两层能力模型

kohane 不依赖任何第三方插件或宿主：它对「能力」有自己的**词表**，对「本机谁提供它」只留一张**本地挂接表**。

```
能力层（随包发布）      Kohane Bassline + 功能词        ← 结果里不出现任何厂商名
本地挂接层（不发布）    $DSH_HOME/library/plugins.local.json  ← 只在 op=provenance 时才显示
```

当前：**291 项能力 / 262 已挂接**。

## 4. 立刻上手

```bash
# 引擎（任选其一）
node kohane-index-desuno/cli/index.mjs                      # 打印用法与工具清单
node kohane-index-desuno/cli/index.mjs sniff <某个文件>      # 立刻识读
node kohane-index-desuno/mcp/index.mjs                      # 作为 MCP stdio 服务

# 桌面工作站（先起桥，再开壳）
node workstation/engine-bridge/server.mjs                   # http://127.0.0.1:8787
workstation/build.ps1                                       # 构建（自动找 VS 的 MSBuild）
```

## 5. 验证：跑得动的才算数

```bash
cd kohane-index-desuno
npm run verify      # = npm run check + npm run selfcheck
```

| 检查 | 证明什么 |
|---|---|
| `check-unicode` | 交付文件都是合法 UTF-8：**任何文字都行，破损不行**（无替换字符、无孤立代理项、无 BOM、无杂控制字符、无回车） |
| `check-consistency` | 文档与分派一致：README/CLI 的工具清单 == 注册表，op 面自洽，无网络调用，库保持安静 |
| `check-portability` | 平台分支各有对应实现（不是只在 Windows 上能跑） |
| `check-isolation` | 交付包不引用兄弟项目、不带厂商品牌 |
| `check-contract` | 每个工具名副其实：键集关闭、op 面自洽、**未知 op 必被拒绝**、只读探针必能应答 |
| `selfcheck` | 端到端回归：**256 项断言**（签名识别、探测、分析器、库不变式、加密、能力目录、索引对账、会话读取、宿主生成） |

当前基线：**16 工具 · 109 签名 · selfcheck 256/256 · 五道检查全绿**。

## 6. 桌面工作站

`workstation/` 是一台 WinUI 3 工作站：**左「即刻分析」**（DiskInfo 式信息密度：状态框、大号读数、两栏属性表）、
**右「图鉴 / 能力」**（索引与能力目录双视图）。视觉主题取自 persona 立绘——
纸白底、正红描边、茶色墨字、藏青表头；**她的表情随文件状态变**（常态 9 张 / 卍解 6 张）。

构建与运行的坑、自检钩子、桥接的库归属，都写在 `workstation/README.md` 里。

## 7. 路线

- **当前**：把本体收干净——顶层文档（本文）、发布元数据、安装验证、CI、契约与不变量已就位
- **下一步**：the local task list (not published) 里的未结项（工作区状态能力的界面深化、能力目录的个人化、发布环节）
- **规划中的追加能力**：**KPB（Kohane Processing Bundle）**——作编混作为 KID 的**封存式 DLC**：
  单独下载、装上生效、卸下复原，**离开 KID 打不开**；内部一律 kohane 自己的容器
  （`.kbb/.kbi/.kba/.kbs/.kbm/.kbw/.kbv`，体积窗口 800 MB–2 GB）。详见
  `the local design notes (kept outside the published tree)`。

## 8. 许可

MIT。见 `kohane-index-desuno/LICENSE`。
