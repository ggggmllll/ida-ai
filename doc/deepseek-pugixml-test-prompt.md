# DeepSeek 黑盒类型还原测试提示词：pugixml

你现在进行一次严格的黑盒逆向类型还原实验。唯一测试对象是 pugixml 的无调试信息 ARM64 ELF 共享库。目标不是复述工具文档，也不是猜测原项目源码，而是使用本地 `ida-ai` 工具，从反汇编、伪代码、结构化 microcode 和 SQLite 证据中建立一组可复核的函数 ABI、对象布局候选和数据流约束。

## 实验边界

- 只能分析这个文件：`D:\IDA Scripts\targets\pugixml\build-ai-stripped-android-arm64-v8a\libpugixml.so`。
- 当前预检 SHA-256 为 `5E5179B8C686A3D828B18555194A79F63F19D58DC020C454E955F2FD7118EC39`；运行实验前重新计算并记录。如果不匹配，先停止并在报告中说明，不要悄悄换成其他构建产物。
- 该文件是 AArch64 ELF64 共享库，没有观察到调试段，但仍保留 ELF 符号表项。IDB 中出现的函数/局部符号名只能作低置信度线索，不能作类型证明。
- 禁止打开、读取、搜索或复制 `D:\IDA Scripts\targets\pugixml` 下的源码、头文件、文档、CMake 文件、构建日志、测试文件、Git 历史和目标目录中的任何源代码派生文本；也不要读取 `zlib`、`tinyxml2` 或 `llvm-project` 的源码。不要联网搜索 pugixml 的源码、API 文档或 ABI 资料。
- 只能使用目标二进制、无界面 IDA 导出的反汇编/伪代码/microcode/flow、SQLite 查询结果，以及 `D:\IDA Scripts\ida-ai\skills` 中的技能说明。二进制残留的符号名可以作为低置信度的“观察线索”，不能当作类型证明；报告中必须把符号名和指令事实分开。
- 不得假设 C++ 类名、虚表布局、继承关系、容器实现、字符串表示、分配器或异常模型。只有在指令和跨函数证据支持时才能提出候选，并保留其他解释。
- 全程使用无界面命令。不要启动 IDA GUI，不要直接修改 SQLite；初始化、导出、刷新和涉及 IDA 的类型操作使用项目已有 CLI/MCP 路径。任何 IDA 类型修改前后都要刷新受影响的视图并记录快照哈希。
- 不得把相同字节宽度当成足以证明的整数、浮点数、指针、数组、虚表指针、结构体字段或 C++ 类型。必须区分 `fact`、`hypothesis`、`decision`、`reject`，并记录冲突、覆盖、联合/重叠视图、大小下界和未解析项。

## 可用环境

项目目录是 `D:\IDA Scripts\ida-ai`，IDA 批处理程序是 `D:\IDA Professional 9.1\idat.exe`。优先把数据库和 IDB 放在目标的构建目录中，避免把实验快照混入项目源码或技能目录：

```text
D:\IDA Scripts\targets\pugixml\build-ai-stripped-android-arm64-v8a\deepseek-pugixml.sqlite
D:\IDA Scripts\targets\pugixml\build-ai-stripped-android-arm64-v8a\deepseek-pugixml.i64
```

如果这两个文件不存在或与目标二进制不一致，在 PowerShell 中执行：

```powershell
& "D:\IDA Scripts\ida-ai\.venv\Scripts\ida-ai.exe" init --binary "D:\IDA Scripts\targets\pugixml\build-ai-stripped-android-arm64-v8a\libpugixml.so" --db "D:\IDA Scripts\targets\pugixml\build-ai-stripped-android-arm64-v8a\deepseek-pugixml.sqlite" --idb "D:\IDA Scripts\targets\pugixml\build-ai-stripped-android-arm64-v8a\deepseek-pugixml.i64" --idat "D:\IDA Professional 9.1\idat.exe"
```

如果目标 `.so` 不存在或哈希不符，停止实验并报告，不要为了继续而读取或重新构建源码。

先阅读并遵守以下技能文件，再执行相应命令：`ida-ai-init`、`ida-ai-sql`、`ida-ai-disassembly`、`ida-ai-pseudocode`、`ida-ai-microcode`、`ida-ai-type-scan`、`ida-ai-type-propagate`、`ida-ai-job-create`、`ida-ai-job-resume`、`ida-ai-job-revise`、`ida-ai-job-show`、`ida-ai-job-check`。命令参数以本地 `--help` 和技能文件为准，不要臆造参数。

## 有界实验流程

1. 先校验输入身份和快照，记录二进制哈希、函数数、段数、交叉引用数、基本块数、CFG 边数、导出状态和失败函数。不要套用 zlib 的数量；第一次得到的数量就是 pugixml 的基线。数量、哈希或 IDB 身份不一致时先重新初始化，不要在漂移快照上继续。
2. 建立根 job，标题可为“pugixml black-box type recovery”，然后根据实际二进制证据拆分 2 至 4 个窄子 job。职责应由观察到的调用/对象行为决定，不能由源码或熟悉的 pugixml API 名称预先决定。每次继续工作前先 `job-resume`；把摘要、开放问题、停止条件和下一最小工作单元保存进 job VCS，发现早期结论有问题时修订或 reject 原 claim，不要无记录地从 A 重放到 E。
3. 从函数图、调用边、参数使用和生命周期行为中选择 4 至 8 个重点函数或紧密关联的函数组。若有残留符号名，先作为线索单独记录，再用寄存器、栈、读写宽度、返回路径和调用边独立验证 ABI。为重点函数导出反汇编、伪代码、microcode 和 flow；需要扩大范围时只加入有明确证据关系的调用者/被调用者。
4. 至少制作三份 utilization-form JSON，并用 `type-scan` 查找实际观察到的利用形式，例如固定偏移读写、成对的地址/长度或范围操作、虚调用/函数指针/回调约束、对象地址传递或状态位掩码。不要为了凑数量编造形式。每份结果都检查 `score`、`matched`、`missing`、`conflicts`、`compatible`、覆盖范围和 microcode hash；`exact` 只表示该形式的局部约束都满足，不能解释为识别了源类型。
5. 至少有一份 form 必须包含 `memory_access.offset` 和一个具体 `width`，用来验证混合宽度修复。除了候选列表，还必须检查返回 JSON 的 `access_profiles`：它收集同一请求数字偏移处所有成功 microcode 的访问，不会因为 `width`/方向筛选而隐藏其他宽度。记录 `width_candidates`、`width_counts`、读写计数、`by_function`、`sample_locations`、`mixed_width` 和 `ambiguities`。数值偏移只相对于该指令的 immediate address base；不同函数、不同基址或不同对象的同偏移不能合并为一个字段。出现 4/8 等多个宽度时不得自动选一个类型、把其余字节写成 padding，或直接宣布 union；逐个检查函数级证据并把替代解释保留为 hypothesis/needs review。
6. 从可复核的 microcode 事实建立 `type-propagate` seed，例如参数、返回值、全局、局部或派生字段视图的指针深度、偏移、读写宽度和调用关系。用有界预算预览引用、参数和返回值传播（建议 `max_hops=3`、`max_nodes=200`、`max_edges=400`、`max_alternatives=8`，具体参数按本地技能说明）。逐条检查完整 trace、transform、conflict、unresolved 和截断原因；只有没有未解决冲突、转换无损且证据独立的 proposal 才能接受。不要把普通 xref 当成别名证明。
7. 第一轮只建立候选，不要为了让伪代码好看而批量应用类型。若一个声明有足够独立证据，最多在单独的 decision revision 中应用三个小改动，然后重新导出受影响函数并记录前后 hash、伪代码变化以及需要复核的 job claim。类型宽度、字段切分、函数指针原型、signedness 和 C++ 语义都必须分别说明证据强度。任何与旧结论冲突的结果写成 reject 或 needs_review，不能覆盖历史 revision。
8. 每个重点函数最多进行三轮“证据→候选→复核”循环；一轮没有新证据就停止。传播达到预算上限时保存 frontier/截断原因并交接下一最小工作单元，不要把“尚未到达”写成“没有使用点”。

## 必须交付的结果

把报告和实验产物写入 `D:\IDA Scripts\ida-ai\agent_reports\deepseek-pugixml\`，不要复制任何目标源码。至少包括：

1. `deepseek-pugixml-type-recovery-report.md`：实际执行的命令、输入哈希、快照指纹、导出状态、覆盖率、失败函数和局限。
2. 至少三份实际使用的 utilization-form JSON 及完整 `type-scan` 结果，包含混合宽度 form 的 `access_profiles` 原始结果。报告中解释为什么某些宽度是候选/歧义，而不是把它们压缩成一个字段。
3. 重点函数的 ABI 候选：参数方向、宽度、指针层数、返回值、调用约束和每项证据地址；符号名线索必须单独标注。
4. 一个或多个对象/视图的候选布局：字段偏移、所有观察到的访问宽度、读/写/传参位置、大小下界、候选类型和置信度。不能证明的字段用 `field_0xNN`；保留 union、重叠视图、数组/指针和共同前缀的可能性。
5. 引用、参数、返回值传播的 accepted proposal、alternatives、conflicts、unresolved、截断原因和完整 trace；至少列出两个被拒绝的错误解释及拒绝依据。
6. 适合人工复核的 C-like 声明和关键函数伪代码。声明必须明确是推断结果，不得声称与 pugixml 源码等价，也不得通过名称补全原始类定义。
7. job 树、每个 job 的最新 revision、fact/hypothesis/decision/reject 摘要、开放问题、handoff、停止条件和需要复核的 claim。最后给出一个下一步最小工作单元，而不是重新开始整棵分析。

实验结束时先运行 `job-check` 检查漂移，再用 SQL 查询逐条核对报告引用的行。最终回复只总结实验完成情况、证据覆盖和未决歧义；不要展示、引用或暗示任何被禁止读取的源文件内容。把“未验证”保留为未验证，禁止用外部资料补齐空白。
