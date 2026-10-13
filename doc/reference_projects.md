# 第一版研究基线

研究前提是无壳、无混淆样本；目标是考察哪些静态分析辅助能让 AI 从反汇编或伪代码恢复功能相同的源代码。第一版先保存可复查的事实（函数、交叉引用、CFG、字节及按需视图），不把反编译输出当作正确源代码。

| 参考项目 | 可复用的思路 | 对本项目的取舍 |
| --- | --- | --- |
| `IDA-NO-MCP-cli/INP.py` | `idat -A -S` 可无界面自动分析与导出。 | 沿用批处理入口，改用 SQLite 和按需导出。 |
| `ida-mcp-next` | `idalib` 可在普通 Python 进程中提供 headless 的函数、xref、反编译与流程图查询。 | 第一版不引入常驻 MCP 服务，保留未来替换 IDA 启动层的可能。 |
| `vdump` | 识别 RTTI、类层次、虚表，已有 `idalib` 模式。 | 作为以后恢复 C++ 类结构的候选数据源。 |
| `ida-vtable-tools` | 提取虚表槽位、方法与类名的启发式逻辑。 | 当前入口使用 `ida_kernwin`、Qt 对话框与交互动作；移植时只取分析逻辑。 |

`IDA-NO-MCP-cli` 交给 AI 的实际产物是一组文本文件：

- `decompile/<函数地址>.c`：成功反编译的函数体，并附函数名、地址、caller/callee。
- `disassembly/<函数地址>.asm`：反编译失败或被跳过时的反汇编回退；成功反编译的函数不会同时保存完整反汇编。
- `strings.txt`、`imports.txt`、`exports.txt`：字符串和符号表。
- `pointers.txt`：数据 xref 加常见数据段中的原始指针，含目标名称、类型与详情。
- `memory/*.txt`：按 1 MiB 分片的十六进制内存转储。
- `function_index.txt`、进度及失败/跳过日志：文件路径、调用关系、回退原因。

其函数导出跳过 `FUNC_LIB`；大于 16 KiB 或 3000 条指令的函数不反编译，而改用反汇编。caller/callee 来自静态交叉引用，未提供完整函数 CFG。第一版 `ida-ai` 因此把 xref 与 CFG 作为初始化事实；反汇编和伪代码分表独立存储，AI 可对同一函数取得两种视图。字符串、导入导出与 C++ RTTI/虚表是后续阶段，不应假定已经包含在本版数据库中。

无 GUI 执行链是 `python -m ida_ai` → `idat -A -Sida_entry.py` → IDA API → SQLite → JSON CLI。仅 IDA 子进程导入 `ida_*` 模块；外部 SQL 查询不启动 IDA。批处理脚本不使用 Qt、剪贴板、菜单或 `ida_kernwin`。初始化保存 IDB，后续按需操作重新打开该 IDB；写入只更新 IDB，之后重建 SQLite 中的函数/xref/CFG 快照。
