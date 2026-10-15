# 变更记录（CHANGELOG）

本文件记录 kohane-index-desuno 的对外变更。格式沿用「新增 / 变更 / 修复」三栏，倒序排列。

## [未发布] 0.1.0

首次成形。此版本尚未发布到 registry。

### 新增

- **引擎（16 工具，MCP stdio + CLI 双入口）**
  - 文件识读：109 条魔数签名、内容探测（不冒认）、声明与实际的**名实不符**检查
  - 库与索引：记录 / 检索 / 对账（`rebuild`、`status`、`audit`、`index`、`verify`、`review`、`prune`）
  - 能力目录：以自有品牌承载插件能力，默认输出**不含厂商名**，本地挂接表可导出/导入
  - 会话读取：多帧压缩帧 + 纯 JSONL + ZIP 归档，时区随响应
  - 工作区状态：一次调用覆盖整个仓库，暂存与工作区分开，逐文件增删行数
  - 音频：`peaks` / `sweep` / `info`，PCM WAV 与 AIFF（含 80-bit 扩展采样率）
  - 加密：敏感对象封存 + **显式复审**（放行或维持封存，两者都留理由）
- **并行**：常驻 worker 池；低于阈值自动退回单核（实测：每次重建的池子会输给 for 循环）
- **桌面工作站**（WinUI 3，另行分发）：即刻分析 + 图鉴/能力双视图，桥接隔离库
- **检查族**：`check-unicode`、`check-consistency`、`check-portability`、`check-isolation`、
  `check-contract` 五道不变量，外加 256 项端到端自检
- **文档**：包内 README（工具与 op 契约）、顶层 README、ARCHITECTURE.md

### 变更

- 「交付文件必须 ASCII」的旧口径改为**编码正确性**：任何文字都可以，但不得有替换字符、孤立代理项、
  BOM、杂控制字符或回车（`check-ascii` → `check-unicode`）
- 工具数与签名数随版本推进：14 → 16 工具

### 修复

- `library_detect` 对未知 op 照做不误 → 现在先拒绝并列出可接受的 op
- 状态栏工具数恒为 0（对桥返回的嵌套数组取根长度）→ 读取 `tools` 字段
- 桥会继承外层 `DSH_HOME` 写进机器级库 → 默认本地隔离，共用需显式开关
- 索引校验把「地址」当「路径」（`scheme://`、`host:port`）→ 已区分
- `review revoke` 对**已封存**记录报错，导致最该判断的记录无法判断 → 改为保留密文并记录判断
