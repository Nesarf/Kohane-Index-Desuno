# kohane-index-desuno · Unity 瀑布可视化

KID 的配套渲染器：把引擎读出来的**谱面**画成下落音符，并把**采样轨的波形画进块里**。

引擎那半边已经齐备，这里只做「看得见」的那一半：

| 引擎接口 | 这里用来做什么 |
|---|---|
| `library_audio op=score` | 音符（音高、起点、时值、力度、所在轨） |
| `library_audio op=peaks` | 采样波形包络（块内波形要用） |

## 怎么跑

1. 先起引擎的本地桥（与 WinUI 工作站用的是同一个）：

   ```bash
   node E:/kohane-index-desuno/workstation/engine-bridge/server.mjs
   ```

2. 让 Unity 知道要看哪一份谱子——三选一：

   - 环境变量 `KOHANE_SCORE=<一份 .mid 的绝对路径>`
   - 在 `Assets/StreamingAssets/kohane-score-path.txt` 里写一行路径
   - 直接在场景里的 `Bootstrap` 上填 `defaultScorePath`

3. 用 Unity 打开本目录（`workstation-unity/`）并播放即可。**不需要手写场景**：相机、灯光与瀑布都在运行时由 `Bootstrap` 搭起来。

## 里面有什么

| 文件 | 作用 |
|---|---|
| `Assets/Scripts/KohaneBridge.cs` | 与本地桥通话，并把引擎的谱面 JSON 映射成本地的数据结构 |
| `Assets/Scripts/Waterfall.cs` | 下落音符：x = 时间、y = 音高、块宽 = 时值、发声增亮、打击轨画菱形 |
| `Assets/Scripts/Bootstrap.cs` | 运行时把场景搭起来，并决定看哪一份谱子 |
| `build.ps1` | 命令行构建（`Unity.exe -batchmode`），用于自验 |

## 与工作站的分别

WinUI 工作站里的那栏瀑布是**软件光栅化**（引擎零依赖原则的延伸，逐像素写）；这里的 Unity 版是**正经三维渲染**，用来做更好看的呈现、块内波形与辉光。两者读的是同一份引擎数据，所以「引擎只管事实、呈现各取所需」这条边界没有被破坏。
