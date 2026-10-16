# DeepSeek 黑盒类型还原测试提示词

你现在进行一次严格的黑盒逆向类型还原实验。目标不是复述工具文档，而是使用本地 `ida-ai` 工具，从没有调试信息的 ARM64 ELF 共享库中恢复一组可审计的函数签名、结构体布局和数据流约束。

## 实验边界

- 唯一目标文件是 `D:\IDA Scripts\targets\zlib\build-ai-stripped-android-arm64-v8a\libz.so`。
- 不得打开或读取 `D:\IDA Scripts\targets\zlib`、`pugixml`、`tinyxml2`、`llvm-project` 中的源码、头文件、CMake 文件、构建日志、Git 历史或测试代码；不得联网搜索 zlib 文档或源码。不要用任何源代码或 ABI 文档验证、补全或纠正结论。
- 只能使用目标二进制、IDA 导出的反汇编/伪代码/microcode/flow、SQLite 查询结果，以及 `D:\IDA Scripts\ida-ai\skills` 中的工具说明。二进制中残留的符号名可以作为低置信度线索，但不能当作类型证明；在报告中标记其来源。
- 全程使用无界面命令。不要启动 IDA GUI，不要直接修改 SQLite；涉及 IDA 类型变更时使用项目已有 MCP/CLI 操作，并在变更前后刷新快照。
- 不得把等宽度当成足以证明的 `int`、`long`、数组、指针或结构体。必须区分事实、假设、决定和拒绝，并记录冲突、覆盖、联合体可能性、大小下界和未解析项。

## 可用环境

项目目录是 `D:\IDA Scripts\ida-ai`，IDA 批处理程序是 `D:\IDA Professional 9.1\idat.exe`。优先使用已准备好的数据库和 IDB：

```text
D:\IDA Scripts\targets\zlib\build-ai-stripped-android-arm64-v8a\deepseek-zlib.sqlite
D:\IDA Scripts\targets\zlib\build-ai-stripped-android-arm64-v8a\deepseek-zlib.i64
```

如果文件不存在或快照不匹配，在 PowerShell 执行：

```powershell
& "D:\IDA Scripts\ida-ai\.venv\Scripts\ida-ai.exe" init --binary "D:\IDA Scripts\targets\zlib\build-ai-stripped-android-arm64-v8a\libz.so" --db "D:\IDA Scripts\targets\zlib\build-ai-stripped-android-arm64-v8a\deepseek-zlib.sqlite" --idb "D:\IDA Scripts\targets\zlib\build-ai-stripped-android-arm64-v8a\deepseek-zlib.i64" --idat "D:\IDA Professional 9.1\idat.exe"
```

先阅读并遵守以下技能文件，再执行对应命令：`ida-ai-init`、`ida-ai-sql`、`ida-ai-disassembly`、`ida-ai-pseudocode`、`ida-ai-microcode`、`ida-ai-type-scan`、`ida-ai-type-propagate`、`ida-ai-job-create`、`ida-ai-job-resume`、`ida-ai-job-revise`、`ida-ai-job-show`、`ida-ai-job-check`。命令参数以本地 `--help` 和技能文件为准，不要臆造参数。

## 有界实验流程

1. 校验快照并记录函数、段、交叉引用、CFG 数量；基线应约为 206 个函数、14 个段、19,605 个交叉引用、3,500 个基本块和 5,156 条 CFG 边。数量不同就说明快照漂移，先重新初始化。
2. 建立根 job“zlib state type recovery”，再基于实际发现的职责拆分出 2 至 4 个窄子 job。每个 job 用 job VCS 保存摘要；每次继续工作前先 `job-resume`，不要从头重放已经完成的函数。
3. 从函数图和数据流中自行挑选一个跨多个阶段传递的状态对象及 3 至 6 个相关函数。不要从函数名直接推断其职责；如符号名可见，先记录为未经验证的线索，再用参数传播、字段偏移、读写宽度和生命周期行为独立验证。先导出相关函数的反汇编、伪代码、microcode 和 flow，再按需扩大到直接调用者/被调用者。
4. 至少制作三份 utilization-form JSON，并用 `type-scan` 在 microcode 中查找：带固定偏移的流状态访问、输入/输出缓冲区与长度的成对读写、回调或函数指针的调用约束。检查每个候选的 score、matched/missing/conflicting、compatible、覆盖范围和 microcode hash；不得把 `exact` 解释成“已经识别出源类型”。
5. 从可复核的 microcode 事实建立 `type-propagate` seed，例如某个参数/返回值/全局/局部节点的指针深度、偏移、读写宽度或调用关系。用有界预算预览引用传播、参数传播和返回值传播（建议 `max_hops=3`、`max_nodes=200`、`max_edges=400`、`max_alternatives=8`，具体参数按本地技能说明）。逐条检查 trace、transform、conflict 和 unresolved；只有没有未解决冲突且证据独立的 proposal 才能接受。
6. 第一轮只形成类型候选，不要为了让伪代码好看而批量改 IDA 类型。若某个声明达到高置信度，可以在单独的 decision revision 中通过已有 MCP 类型操作应用最多三个小改动，然后重新导出受影响函数并记录前后 hash、变化和需要复核的 job claims。任何与旧结论冲突的结果都写成 reject 或 needs_review，不能覆盖历史 revision。
7. 每个函数最多进行三轮“证据→候选→复核”循环；一轮没有新证据就停止。发现早期结论可能错误时，从对应 job resume，修订或拒绝原 claim，并从受影响的子 job 继续；禁止无记录地重新执行 A 到 E。

## 必须交付的结果

在 `D:\IDA Scripts\ida-ai\agent_reports\deepseek-zlib\` 写出报告和所有 utilization-form JSON；不要复制任何原项目源码。报告至少包括：

1. 实际执行过的命令、快照指纹、导出状态、覆盖率和失败函数。
2. 六个重点函数的 ABI 候选（参数方向、宽度、指针层数、返回值）及每项证据地址；将符号名线索与指令事实分开。
3. 所选状态对象及关联内部状态的候选布局：字段偏移、访问宽度、读/写/传参位置、大小下界、候选类型和置信度。不能证明的字段用 `field_0xNN`，不要编造语义名称。
4. 引用、参数、返回值传播的 accepted proposal、alternatives、conflicts、unresolved、截断原因和完整 trace；给出至少两个被拒绝的错误解释及拒绝依据。
5. 适合人工复核的 C-like 声明和关键函数伪代码。声明必须注明“推断”，不要声称与真实源代码等价；列出仍可能是 union、重叠结构、数组或指针的地方。
6. job 树、每个 job 的最新 revision、fact/hypothesis/decision/reject 摘要、开放问题、handoff、停止条件和需要复核的 claim。最后给出下一步最小工作单元，不要重新开始整个分析。

实验结束时，先运行 `job-check` 检查漂移，再用 SQL 查询核对报告引用的行。最终回复只总结已完成的实验、证据覆盖和未决歧义；不要展示或引用任何被禁止读取的源文件内容。
