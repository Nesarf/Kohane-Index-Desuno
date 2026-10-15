# P1 攻坚记录：索引对账三件事（audit / index / verify / review / prune）

日期：2026-09-11（同日第十一轮）　落点：`lib/core.mjs`（`library_index`）+ `tools/selfcheck.mjs`
契约来源：兄弟构建 `mega-index-map` v0.3.3 的 `library_index` 描述（只读参照，按 kohane 口径重写）。

## 一、为什么是「三件事」而不是一个功能

索引有三类互不相同的问题，混在一起就会互相骗：

| 问题 | op | 关键纪律 |
|---|---|---|
| 盘上有、库里从没记过 | `audit`（只读）+ `index`（写入，需 confirm） | 对账**双向**：既报未记录，也报记录在册却已不在的；`index` **拒绝盘根**（会走全盘的索引器正是本库要替代的扫描），且**敏感名逐条跳过**，绝不批量加密 |
| 记在册的东西还指着真实存在的东西吗 | `verify` | 比的是**身份**不是存在：`unchanged / changed / gone / never`；默认只读，`confirm:true` 才写回观测到的指纹（这就是建基线的方式）；带时间预算与 `after` 游标，大库分批走 |
| 被封存的记录，是**有人判断过**才封的吗 | `review` | `what=sealed` 列未被判断的加密记录；`what=candidates` 列「按当前规则本来会被封」的可读记录（改规则后必跑）；`id + clear|revoke + reason` 才动一条，**逐条、不按名字或规则批量**、必进日志，清空后的记录带着「放行它的那次复审」 |

`prune` 只做确认后的事：`dead`（路径**可验证地**消失）、`hollow`（只剩名字——写坏的产物）、
`leads`（本库没有 mining 派生行，如实回报「无可收紧」）。`status` 一次只读读给出账本全貌 + 最近一次盘侧结论（从 append-only 日志回读，不再走盘）。

## 二、实机抓到的两个真问题（价值就在这）

对着**真实库（11,442 个对象）**跑，立刻暴露：

1. **地址被当成路径**：`verify` 把 `path: "http://127.0.0.1:8100"` 的服务端点报成「已消失的文件」（4 例）。
   契约里明明写着「地址不是路径」——我的 `recordPath()` 当时只判空。
   → 新增 `looksLikeFilePath()`：`scheme://`、裸 `IP:port`、`host:port` 一律视为**地址**；
   盘符绝对路径、UNC、POSIX 绝对路径、含分隔符者才算路径。
   修复后 `total` 9662 → **9249**（413 个地址被正确排除），`gone` 4 → **1**（剩下的 `C:\pagefile.sys` 确实取不到，属真话）。
2. **基线缺失是常态**：9249 条带路径的记录里 **385/386 从未录过指纹**（库早于指纹机制）。这是 `verify confirm:true` 存在的意义——
   但**批量写真实库要由 sensei 点头**，我没有擅自跑。

另外 `review what=sealed` 在真实库上给出 **11 条**「封了却没人判断过」的记录——这正是该工作流的用武之地（逐条 `clear` 或 `revoke`）。

## 三、同时补齐的 P1 小项

- **`library_plugin op=unlinked`**：报「本机没有任何插件提供」的能力槽；
- **`library_plugin op=numbered`**：报仍带编号兜底名（`Delay 2` / `Meter 2`）的条目，配合 `op=rename` 逐条命名；
- **会话撕裂帧的二次确认**：帧边界靠魔数切分，而魔数可能出现在压缩数据内部 → 现在**解不开的块会先与后一块合并重试**，只有仍然失败才算撕裂（真损坏与切分误判因此可区分）。

## 四、验证

| 项 | 结果 |
|---|---|
| `tools/selfcheck.mjs` | **215/215 全绿**（新增约 32 条：对账双向、audit 只读、index 拒盘根/需 confirm/不批量加密、verify 四分类与基线、review sealed/candidates/clear/revoke 与「无 reason 即拒」、prune dead/hollow/leads、status、地址非路径） |
| 四道不变量检查 | ascii / consistency / portability / isolation **全绿**（consistency 的 op 一致性规则同时修好：取分派自己的 `allowed:` 列表，而不是子决策的小列表） |
| `reference-check` | 只读无差异 |

## 五、仍未做（P1 剩余）

- 能力挂接跨机迁移（`export-links` / `import-links`）；
- `.map` 色带的内容探测型名称规则；
- 69 个 `unknown` 角色的第三级证据——**本机只有 1 个 `moduleinfo.json`，此路在本机低产**，暂缓；
- `library_adb` 真机端到端（本机无设备）；密钥轮换。
---

## 六、真库动作（sensei 授权后执行，同日第十一轮尾）

### 6.1 指纹基线建立
`library_index --op verify --confirm true`，7 个切片、202 秒：

| 项 | 值 |
|---|---|
| 检查 | **9250** 条带路径记录 |
| 录得指纹 | **9247**（此前 0） |
| 变更 | 0 |
| 路径真消失 | 3 |

→ 从此这 9247 条记录有了**身份基线**：日后 `verify` 能区分「内容变了」与「路径没了」，
不再只有「存在/不存在」。

### 6.2 12 条封存记录的复审
判据（先分开「材料」与「提及」）：
- **材料**：私钥块 / `AIza…` / `sk-…` / `AKIA…` / 证书 / 赋值给凭据词的值 / 无分隔符的长不透明串；
- **提及**：记录里出现「credentials / api-key / password / pfx / token」等**文件名或路径**。

结果：**12 条里没有一条记录本身携带材料**；8 条只是「指向凭据文件」，2 条是隔离区的未知下载，
4 条两者皆无（其中 2 条是普通知识笔记，另 2 条是同一隔离下载）。

逐条落定（每条都带理由进 append-only 日志）：

| 决定 | 条数 | 例 |
|---|---|---|
| `clear`（放行） | **2** | `CocoStudio .csb schema` 知识笔记、`MSPCManager 进程` 知识笔记——既无材料也无凭据指向 |
| `revoke`（维持封存 + 记下判断） | **10** | `.credentials.yaml`、`gemini-api-key.txt`、`.api-key.txt`、`pfx-password.txt`、密钥落点 env、签名材料、两个隔离下载 |

收尾状态：`what=sealed` → **0**（不再有「封了却没人看过」的记录）；库现状 **11443 对象 / 10 加密 / 12 已复审 / 9247 已录指纹**。

### 6.3 顺带修掉的一个语义缺陷
`review revoke` 原本对「**已经**封存」的记录直接报错（「already encrypted」），
于是最需要判断的那批记录反而无法被判断。已改为：**已封存 → 保留密文 + 记录判断**；
只有「可读」的才重新封存。这条已进自检。

## 七、本轮验证汇总

`selfcheck` **237/237** · 四道不变量检查全绿 · `reference-check` 只读无差异 · MCP = 14 工具。
