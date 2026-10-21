# DeepSeek LLVM 虚表增量覆盖测试（round4）

这是一次小范围覆盖实验，不是第二轮完整盲测的重跑。round2 报告已经冻结；round3 只导出了一个按直接调用引用挑选的函数，该函数有 275 个直接 `call`、0 个 `icall`，没有进入虚调用检测分母。本轮的目的，是先用原始指令确认候选函数确实含间接 `call`，然后只导出一个新函数的 GLBOPT3 微码，测量检测器在新函数上的实际覆盖。

## 不可改变的边界

- 唯一目标：`D:\IDA Scripts\targets\llvm-project\build-ai-stripped\bin\clang.exe`。
- 启动前和结束后计算 SHA-256，必须为 `F614FAF7843DCD49A0712AE68997315144CA53B3281F8140B85FCB8569A7944C`；不一致立即停止。
- 不得读取 LLVM 源码、头文件、构建配置/日志、调试数据、Git 历史或源码对照评估。不要打开 round1/round2 报告正文、audit 答案或 round3 结果来推断目标真值；round2 只按哈希和 SQLite 只读查询作为冻结基线。
- 从冻结的 `agent_reports\deepseek-llvm-round2\clang.sqlite` 和 `clang.i64` 复制到新的 `agent_reports\deepseek-llvm-round4\`。不要从 round3 复制，因为 round3 已有局部刷新和 stale 状态。
- 复制后只在 round4 副本执行 schema 迁移和 `metadata.idb_path` 重绑定；不得修改 round2 文件、round2 IDB、round2 报告、round2 jobs 或 round2 manifest。保存重绑定前后的路径和哈希。
- 使用 `.venv\Scripts\python.exe`。所有命令、参数、超时、stdout/stderr、退出码、耗时和 round4 DB/IDB 前后哈希写入 `round4\logs\`。
- 不做全库 GLBOPT3、全库伪代码、全库表重建、类型 apply 或大范围 fixup 扫描。没有合适候选时停止，不通过扩大预算制造成功案例。

## 先找真实的间接调用

不要用“直接 call xref 数量”作为唯一选择标准。先在 round4 副本做轻量候选预扫描，优先使用 IDA 已保存的指令/反汇编；如果当前 SQLite 没有足够的指令行，使用一个只读、一次性的 IDAPython headless 扫描，读取函数边界和指令操作数，不生成 microcode、不写分析结果。扫描结果只保存候选 EA、函数大小、指令 EA、助记符/操作数字符串和判定理由。

在 x86-64 中，将以下情况标为 raw indirect call candidate：

- `call rax`、`call rcx` 等寄存器目标；
- `call [reg+offset]`、`call qword ptr [rip+offset]` 等内存目标；
- 其他无法从指令编码直接确定固定目标的 `call` 操作数。

固定相对目标的 `call rel32`、已解析为固定函数入口的直接调用不要计入 raw indirect call。`jmp`/尾调用另列，不要混入 call 分母。导入表间接调用仍是 raw indirect call，但要在报告中单独分类。不要因为函数名、C++ 符号或 `_ZTV` 名称就断定它是虚调用。

候选必须同时满足：

1. 不属于 round2 基线中 48 个成功的 `MMAT_GLBOPT3` 函数；
2. raw 指令扫描至少发现一个间接 `call`；
3. 函数大小适合单函数限时导出，优先选择 1 KB–50 KB 范围内 raw indirect call 数最多的函数；若其导出预计过大，选择下一个并记录原因。

把候选列表和筛选 SQL/扫描日志保存下来。候选选择是覆盖实验的操作依据，不是虚调用语义证据。

## 只导出一个函数

对选定函数执行一次：

```text
.venv\Scripts\python.exe -m ida_ai export microcode --db ROUND4.sqlite --idat "D:\IDA Professional 9.1\idat.exe" --timeout 300 --address FUNCTION_EA
```

随后只对同一函数运行：

```text
.venv\Scripts\python.exe -m ida_ai vcall-build --db ROUND4.sqlite --idat "D:\IDA Professional 9.1\idat.exe" --timeout 300 --max-calls 5000 --address FUNCTION_EA
```

用 SQL 核对：

- `microcode` 的 maturity、status、instruction_count、content_hash；
- `micro_instructions` 中 `call`、`icall` 和其他 call-like opcode 的计数；
- raw indirect call 数与 microcode `icall` 数的差异；
- `vcall_sites` 的总数、candidate 数、unknown 数及 unknown reason；
- `vptr_writes`、缺失、错误、预算截断和源 snapshot hash。

如果 raw indirect call 存在但 microcode 没有 `icall`，记录为“形态/导出差异”，不要称为 detector 漏报。若出现至少一个 `vcall_site`，最多选择一个站点执行 `vcall-analyze`；只有在该站点有必要时再执行一档小预算 `vcall-trace`（hops=1、nodes=50、edges=200、alternatives=8、context=3）。没有站点就停止，不再追加函数。不要为了得到 trace 成功而导出 caller/callee。

## job 与失效

在 round4 建立一个新的增量 job，记录 raw 预扫描、函数选择、导出、调用索引和结果。保留 fact/hypothesis/decision/reject 区分，并把每个 raw 指令和 SQL 行作为证据。单函数刷新触发的旧 vcall/vptr/job stale 或 review 是预期行为：保存 `job_review`，不要恢复、删除或解决继承的 round2 claims。不要把 round2 的 101/328 分母与本轮单函数分母合并。

## 交付物

在 `agent_reports\deepseek-llvm-round4\` 保存：

- `deepseek-llvm-vtable-round4-report.md`：身份、隔离、候选扫描方法、选中函数、raw indirect call 证据、导出和 detector 结果、失败/未覆盖及停止理由；
- `round4-preflight.json`、完整命令日志、候选列表和 SQL 核验；
- 如有站点，保存一个 analyze/trace 的原始 JSON；没有站点则明确写“本轮无 trace”；
- round4 DB/IDB 副本的最终哈希；round2 冻结 DB/IDB/报告/manifest 的前后哈希；目标二进制前后哈希；
- `artifact-manifest.json` 和对应 SHA-256 文件。

结论只能回答：这一个经过 raw indirect-call 预筛选的函数是否成功导出、实际有多少 raw indirect call、多少 `icall`、多少 detector site/unknown，以及工具在哪一步保留了 unknown。不要计算全 clang precision/recall，不要把结构候选写成运行时目标，也不要把没有执行的步骤写成通过。
