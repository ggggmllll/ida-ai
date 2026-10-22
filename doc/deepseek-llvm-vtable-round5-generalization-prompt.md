# DeepSeek LLVM 虚表检测器泛化测试（round5）

本轮验证已提交的 vcall detector v6 是否能在 round4 以外的一个函数上识别“加载指针作为调用参数 → 从该指针加载 vptr → 常量槽位加载”的结构。结构候选仍不是已确认的 C++ 虚调用，也不证明运行时目标。本轮只导出一个函数，不做全库扫描或精确率/召回率结论。

## 固定范围与隔离

- 目标二进制：`D:\IDA Scripts\targets\llvm-project\build-ai-stripped\bin\clang.exe`。
- 目标函数：`0x1416365A0`。这是 round4 轻量 raw 指令筛选得到的第二个函数候选，约 48 KB，含大量 raw indirect call；选择只用于覆盖测试，不代表这些调用是虚调用。
- 不要重新选择其他函数，也不要因为检测器没有产出候选而扩大范围。
- round2 的 48 个 GLBOPT3 成功函数及 round4 的 `0x144B89D70` 都不属于本轮目标。不得将它们的调用计入本轮分母。
- 开始和结束时核验目标 SHA-256 为 `F614FAF7843DCD49A0712AE68997315144CA53B3281F8140B85FCB8569A7944C`；不匹配立即停止。
- 从冻结的 `agent_reports\deepseek-llvm-round2\clang.sqlite` 和 `clang.i64` 复制到新的 `agent_reports\deepseek-llvm-round5\`。round2 和 round4 的数据库、IDB、报告、jobs、manifest 均只读；不得从 round4 副本继续工作。
- round5 副本可做必要的 schema 迁移和 `metadata.idb_path` 重绑定，须记录变更前后路径、哈希及 SQLite `quick_check`。
- 使用 `.venv\Scripts\python.exe`。所有命令、参数、耗时、stdout/stderr、退出码和 round5 DB/IDB 哈希写入 `round5\logs\`。
- 不读 LLVM 源码、头文件、构建配置/日志或调试信息；不打开 round4 报告正文或 round4 的站点分析结果。不要用函数名、符号名、类名或表名推断语义。
- 开始前阅读本轮涉及的 vcall build/analyze/show 与 job skills；命令参数以 skills 和本机 `--help` 为准。

## 实验步骤

1. 记录 round2 冻结输入哈希与函数元数据；只确认 `0x1416365A0` 是一个函数、在大小限制内，并核对它不属于 round2 的 48 个成功 GLBOPT3 函数。不得导出其他函数。
2. 对该函数导出一次 GLBOPT3 microcode：

   ```text
   .venv\Scripts\python.exe -m ida_ai export microcode --db ROUND5.sqlite --idat "D:\IDA Professional 9.1\idat.exe" --timeout 300 --address 0x1416365A0
   ```

3. 对同一函数运行一次 vcall-build：

   ```text
   .venv\Scripts\python.exe -m ida_ai vcall-build --db ROUND5.sqlite --idat "D:\IDA Professional 9.1\idat.exe" --timeout 300 --max-calls 5000 --address 0x1416365A0
   ```

   不使用 `--all`，不刷新其他函数，不运行全库 vtable build。

4. 用 SQL 核对该函数的 microcode maturity/status/instruction_count/hash、call-like opcode 数、vcall site 总数、候选数、unknown 数及 reason、预算/导出状态、vptr-write 数和 source hash。检查候选中 `basis=loaded_pointer_receiver_then_vptr_and_constant_slot` 的数量，并抽查其保存的 pointer-field offset、vptr/slot load EA、constant slot offset、参数 identity binding 与 definition chain。验证结构不完整或参数绑定失败的站点是否仍为 unknown。
5. 若本轮至少产生一个 site，最多对其中一个代表性站点运行 `vcall-analyze`，保存原始 JSON。只说明兼容槽位数与 unknown frontier；不得把兼容目标写成运行时目标或计算概率。不要运行 `vcall-trace`，不要再导出 caller/callee。
6. 建立一个新的 round5 job，记录导出、检测、SQL 快照和分析结果；区分 fact、hypothesis、decision、reject。不要修改或恢复继承自 round2 的 job claim。
7. 结束时重新核验目标、round2 冻结输入和 round5 副本哈希。生成 report、日志索引、SQL 结果、artifact manifest 与 manifest SHA-256，并验证 manifest 全部条目。

## 交付与结论边界

在 `agent_reports\deepseek-llvm-round5\` 保存报告和完整原始日志。报告至少给出目标及输入哈希、隔离过程、microcode 导出结果、raw call 与 microcode call-like 计数、vcall site/candidate/unknown 分布、v6 结构证据抽查、一次 analyze（若执行）、失败/截断/未覆盖和停止理由。

只回答这个函数上 v6 是否观察到该结构、结构候选保存了什么证据、哪些站点留在 unknown，以及 analyze 暴露了哪些 unresolved frontier。不要声称对全 clang 具有 precision/recall，不要声称候选已确认是虚调用，不要声称运行时 target 已确定，不得读取源码来验证答案。
