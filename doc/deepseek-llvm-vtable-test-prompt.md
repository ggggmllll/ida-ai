# DeepSeek 虚表与虚调用盲测提示词：LLVM clang.exe

你将执行一次虚表候选、函数内 vptr 写入和虚调用分析的黑盒盲测。实验目标是判断工具在大型、去调试信息的 C++ 二进制上能否提供可复核证据，不能把候选索引或匹配分数写成已证明的类层次或运行时目标。

## 目标和实验边界

- 唯一目标文件：`D:\IDA Scripts\targets\llvm-project\build-ai-stripped\bin\clang.exe`。
- 预检 SHA-256：`F614FAF7843DCD49A0712AE68997315144CA53B3281F8140B85FCB8569A7944C`。启动前重新计算；不一致则停止并报告，不要替换样本。
- 构建配置的只读预检显示这是 x86-64、Release、`LLVM_ENABLE_RTTI=OFF` 的构建。不得把缺失 RTTI 解读为没有 C++ 多态；不得要求用 RTTI 类层次为结果评分。
- 盲测报告完成前，禁止打开、读取、搜索或引用 `D:\IDA Scripts\targets\llvm-project` 中的源代码、头文件、CMake 配置、构建日志、测试文件、Git 历史或其他源代码派生内容。禁止联网查询 LLVM 源码/API/类定义。允许验证二进制哈希和读取本提示词明确给出的构建元数据。
- 先完成黑盒报告并保存/提交 job VCS 摘要，再另建源码对照评估阶段。任何源码对照只用于之后计算评测指标，不能倒灌修改盲测结论；保留盲测报告原件。
- 仅使用目标二进制、IDA 无界面导出的分析数据、SQLite 查询、CLI/MCP，以及 `D:\IDA Scripts\ida-ai\skills`。不得启动 IDA GUI，不要直接改 SQLite。不要读取其它 targets 样本。
- 把 IDA 中残留符号名作为低置信度线索单独记录。不要由名称直接断言函数职责、类名、继承、对象布局或虚函数语义。
- 结论必须分为 `fact`、`hypothesis`、`decision`、`reject`。虚表候选、RTTI 描述符基类边、同槽号、函数名或一次 vptr 写入都不能单独证明对象的动态类型和运行时可达性。未知、别名、覆盖写、间接调用、副作用、构造/析构阶段、外部模块和扫描截断必须保留。

## 工具和本地产物

项目目录：`D:\IDA Scripts\ida-ai`。IDA 批处理程序：`D:\IDA Professional 9.1\idat.exe`。仅在不存在独立快照时初始化；不要覆盖其它数据库：

```text
D:\IDA Scripts\ida-ai\agent_reports\deepseek-llvm\clang.sqlite
D:\IDA Scripts\ida-ai\agent_reports\deepseek-llvm\clang.i64
```

使用 PowerShell 校验样本：

```powershell
Get-FileHash -LiteralPath 'D:\IDA Scripts\targets\llvm-project\build-ai-stripped\bin\clang.exe' -Algorithm SHA256
```

若需新建分析快照：

```powershell
& 'D:\IDA Scripts\ida-ai\.venv\Scripts\ida-ai.exe' init --binary 'D:\IDA Scripts\targets\llvm-project\build-ai-stripped\bin\clang.exe' --db 'D:\IDA Scripts\ida-ai\agent_reports\deepseek-llvm\clang.sqlite' --idb 'D:\IDA Scripts\ida-ai\agent_reports\deepseek-llvm\clang.i64' --idat 'D:\IDA Professional 9.1\idat.exe'
```

报告和全部实验产物写入 `D:\IDA Scripts\ida-ai\agent_reports\deepseek-llvm\`；该目录由仓库 `.gitignore` 排除。提交代码仓库时不要强制添加这些本地报告、数据库、IDB 或缓存。

开始前阅读相关 skills：`ida-ai-init`、`ida-ai-sql`、`ida-ai-job-create`、`ida-ai-job-resume`、`ida-ai-job-revise`、`ida-ai-job-show`、`ida-ai-job-check`、`ida-ai-vtable-build`、`ida-ai-vtable-list`、`ida-ai-vtable-show`、`ida-ai-vtable-search`、`ida-ai-vcall-build`、`ida-ai-vcall-analyze`、`ida-ai-vcall-show`、`ida-ai-vptr-write-build`、`ida-ai-vptr-write-list`、`ida-ai-microcode`、`ida-ai-disassembly`、`ida-ai-pseudocode`。CLI 参数以技能和本地 `--help` 为准。

## 有界执行流程

1. 复算 hash，记录 IDA/SQLite 二进制身份。初始化后先保存函数数、段数、xref 数、基本块和 CFG 边数、扫描范围、错误与导出覆盖。不能把 LLVM 的全部 183 MB 文件假设为已完整导出；明确记录昂贵步骤的范围和预算。
2. 建立根 job“LLVM clang virtual dispatch recovery”，按实测证据拆 3 至 5 个窄子 job，例如表候选/边界、vptr 写入、调用模式/槽位、跨函数对象来源和误报审计。子 job 必须由观察结果决定，不要照搬 pugixml/zlib 的结论。每次续作前先 `job-resume`，写清前序摘要、开放问题、stop condition 和 next smallest unit。
3. 先运行有界 `vtable-build --abi itanium`，记录候选数、槽位数、扫描字节/段覆盖、前缀覆盖、候选边界、空槽、thunk/nullstub/library/runtime 分类、RTTI 描述符覆盖和未知/截断。该样本关闭 RTTI，若解析为零就如实记录，不要据此排除 vtables。候选可以来自回调表或 C ops 表，需主动抽样做误报检查。
4. 不要第一轮对整个 clang 导出所有伪代码。选择有代表性的有限范围/函数子集，导出 GLBOPT3 microcode，再运行 `vcall-build`。检查调用点召回覆盖、候选链、receiver argument identity/offset、未知 indirect-call 和失败函数。记录具体 block/ordinal/EA，而不只写函数名。
5. 在已有当前虚表索引后，对同一批函数运行 `vptr-write-build`，或直接使用会刷新微码并同时索引 vptr 写入与调用的 `vcall-build`。抽样核对 store 的 value 定义链、对象 identity、vptr offset、address point 和 CFG 顺序。`vptr-write` 是精确观察到的存储候选，不等于构造函数或存活对象状态。
6. 对重点 call 使用 `vcall-analyze` 和 `vcall-show`，检查兼容 slot、prior vptr store candidate、thunk 链、槽位分类、unknown frontier 和 source hash。相同槽偏移只产生兼容候选；同函数先前 store 仍无法排除 alias write、调用副作用、对象生命周期或其他未索引路径。
7. 所有大范围操作使用明确预算和范围；逐步增加样本，不因“0 个候选”就扩大到无上限。每次至少记录命令参数、扫描范围、时间、DB 快照 hash、missing/error/truncated 数。若一次循环没有新证据，停止该分支并写 handoff，不从头重放。
8. 不要为美化伪代码应用类型。只在单独决策 revision 记录经独立证据支持的有限修改；修改后同步 IDA 与 SQLite，保存受影响函数的前后 microcode/pseudocode hash，并运行 `job-check`。
9. 盲测结果冻结之后，才允许创建“源码对照评估”阶段。先固定 ground truth 构建身份和评估规则，再对盲测候选计算 precision/recall、槽位/边界误差、目标集合召回与误增、覆盖/unknown/truncated、证据可回查率、上下文成本和 job resume 后重复分析比例。源码对照差异追加新 job revision，不覆盖初始盲测结论。

## 交付物

至少提供：

1. `deepseek-llvm-vtable-report.md`：哈希、构建元数据、数据库身份、实际命令、候选/槽位/写入/调用覆盖、预算、错误与限制。
2. 根 job 与子 job 树、每个 head revision 的事实/假设/决定/拒绝摘要、handoff、开放问题、需复核 claim 和停止条件。
3. 至少 10 个重点候选的可复查样例：vtable candidate、slot、vptr write、call site 与 analyze 结果之间的关联；每项带 EA、candidate/call/write ID、微码 block/ordinal、hash、slot offset 和 unknown frontier。至少包括 3 个支持案例、3 个可疑误报/被排除案例；若总体规模不足，应报告真实数量和覆盖缺口。
4. 对构造/析构多次写入、次级表、thunk/nullstub、同实现合并、回调/C ops 数组、普通 indirect call、缺 RTTI 和 external/unknown case 的观察。没有观察到的分类明确写“未覆盖”，不要编造样例。
5. 一个阶段冻结的盲测结论，和单独的源码对照评估结果。不得把调试信息、头文件或源代码推出的知识写入盲测章节。
6. 完整机器可读产物：命令输出 JSON、SQL 核验、样例清单、job revision export，以及 coverage/统计脚本。最终运行 `job-check` 并用只读 SQL 逐条核对报告引用的 ID 和地址。

最终回复简要说明实验完成范围、覆盖和误报/歧义。不能用 RTTI 关闭推断“没有 C++ 虚调用”，也不能把工具候选称为已证明事实。
