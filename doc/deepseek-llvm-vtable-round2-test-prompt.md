# DeepSeek 第二轮 LLVM 虚表功能盲测

你是独立逆向测试者。请在 `D:\IDA Scripts\ida-ai` 使用现有 CLI/MCP 和对应 skills，测试虚表引擎首版，重点验证最近新增的程序点内存追踪与有界跨函数路径。交付真实证据、失败和覆盖缺口，不以“找到一个候选”作为恢复成功。不要修改工程实现；发现 bug 后保存最小复现与原始输出。

## 1. 身份与隔离（先完成）

唯一目标：`D:\IDA Scripts\targets\llvm-project\build-ai-stripped\bin\clang.exe`。

启动前重算 SHA-256，必须为 `F614FAF7843DCD49A0712AE68997315144CA53B3281F8140B85FCB8569A7944C`；不一致立即停止。已知实验背景仅为 x86-64、Release、RTTI OFF。记录当前 ida-ai commit 和工具版本，不阅读 Git diff/log 中的测试答案。

禁止读取目标项目的源码、头文件、构建配置/日志、调试数据、测试布局或 Git 历史；禁止联网查 LLVM 源码/API/类布局。禁止阅读首轮源码对照评估、detector audit、本项目合成测试及其预期输出来充当自己的发现。可使用二进制本身、IDA 观察、对应 skills、CLI help 和导出契约；符号名称只作为低置信度线索。遇到工具调用问题可定位工具实现，但不能借测试夹具预知目标答案。

本轮目录为 `D:\IDA Scripts\ida-ai\agent_reports\deepseek-llvm-round2\`。首轮 `agent_reports\deepseek-llvm\` 的 `clang.sqlite`、`clang.i64`、报告及相关文件是冻结产物，禁止工具连接/迁移或启动其 IDB。先只读记录首轮 DB、IDB、报告的 SHA-256、大小，再复制 DB 和 IDB 到本轮目录；结束复算原文件哈希。不要打开首轮报告正文。不得在 IDA 仍持有文件或 SQLite WAL 尚未归并时直接复制：停止并报告占用，或通过 SQLite 只读 backup API 得到一致副本（包含 WAL 的已提交内容）。记录采用的方法。

**关键：只复制 SQLite 不够，metadata.idb_path 仍指向原 IDB。** 在任何 CLI/MCP 调用前，只对副本做以下维护重绑定。允许的 SQLite 写入例外仅为这一个路径键；禁止改造观察、索引或结果行制造证据：

```python
from pathlib import Path
from contextlib import closing
from ida_ai.db import connect, get_metadata, set_metadata

root = Path(r'D:\IDA Scripts\ida-ai\agent_reports\deepseek-llvm-round2').resolve()
db = root / 'clang.sqlite'
idb = root / 'clang.i64'
assert db.is_file() and idb.is_file()
assert db.resolve().parent == root and idb.resolve().parent == root
with closing(connect(db)) as c:  # 迁移只发生在副本
    previous = get_metadata(c, 'idb_path')
    set_metadata(c, {'idb_path': str(idb)})
    c.commit()
    assert Path(get_metadata(c, 'idb_path')).resolve() == idb
print({'previous_idb_path': previous, 'isolated_idb_path': str(idb)})
```

使用 `.venv\Scripts\python.exe` 执行并保留维护日志。再次检查所有命令的 `--db`、MCP 配置和解析后的 IDB 路径均在 round2 目录。任何不满足隔离条件的操作立即停止。本轮不重新 init 全部 clang，也不对全库重新反编译。

## 2. 工具和研究记录

先读 `skills/ida-ai-vtable-build`、`ida-ai-vtable-list/show/search`、`ida-ai-vcall-build/analyze/show/trace/trace-show`、`ida-ai-vptr-write-build/list/trace` 对应目录下的 SKILL.md。实际使用 flow、SQL、job、关系或类型工具时再读对应 skill；flow 使用 `export --view flow`，不要猜不存在的 `flow` 命令。命令入口为 `.venv\Scripts\python.exe -m ida_ai`。用 help 核实参数，地址字符串使用十六进制。

建立根 job“LLVM round2 vtable validation”，子 job 按表观察、调用/内存、跨函数、失效与门控拆分。每步先 resume，保存 fact/hypothesis/decision/reject、证据 ID/EA/hash、详细 revision、下一步和停止条件。不能把工具候选直接写成 class fact。遇到无新证据的循环停止该分支；上游变化后只恢复首个受影响环节。使用 `vtrace:<run_id>` 引用 trace，并验证 job-check 是否发现过期证据。不要为达到零 review 自动恢复缺少证据的 claim。

先保存副本基线（schema、函数/段/CFG/xref、各 maturity 覆盖、当前索引、job 状态）。旧索引可能不符合新规则：明确重建并保存新 run，不混算旧候选。先在已有微码的有限函数集合运行 `vcall-build --no-refresh`，统计所有间接调用、结构候选与每类 unknown；不要只统计成功候选。

常用命令形态如下，实际选择器和参数以 help/skill 为准：

```text
python -m ida_ai vcall-build --db ROUND2.sqlite --address FUNCTION_EA --no-refresh
python -m ida_ai vcall-analyze --db ROUND2.sqlite --call-id CALL_ID
python -m ida_ai vcall-trace --db ROUND2.sqlite --call-id CALL_ID --max-hops 3 --max-nodes 200 --max-edges 2000 --max-alternatives 8 --max-context 3
python -m ida_ai vcall-trace-show --db ROUND2.sqlite --run-id RUN_ID
python -m ida_ai export --db ROUND2.sqlite --view flow --address FUNCTION_EA
```

## 3. 实验任务与预算

1. **数据与表观察。** 在副本重建表索引，区分 `--no-refresh` 复用旧观察与真实 IDA 刷新。若需验证新增 fixup，先选一个明确的只读数据半开区间，真实 `vtable-build --range ... --max-bytes ...`；保存扫描范围、字节预算、fixup API/错误/截断覆盖。SQL 核验 `data_fixups` 的源 EA、类型、off/base/displacement 和 loaded bytes。加载字节不是磁盘原字节，fixup 元数据不自动证明运行时目标。范围内没有 fixup 应报告零观察，不能编造“已验证重定位解析”。范围重建可能使原索引 stale，后续使用当前有效范围或显式离线全观察重建。
2. **表与 thunk。** 独立选择表候选，核验边界、前缀、空槽、nullstub、原始入口与 thunk 链；按实现/链中地址反查，并组合多个目标。记录未导出终点、循环/预算和未知 this/返回调整；无可用多跳实例就写未覆盖。无 RTTI 不等于无继承；普通回调表仍可能满足结构模式。
3. **调用识别。** 检查拆分和嵌套双加载、零槽偏移、receiver 实参绑定；分别核验 vptr offset、slot byte offset、对象投影。普通单间接调用、动态偏移、缺定义、表达式截断保持 unknown。独立记录实际检测覆盖，不引用首轮审计中的候选数量作为答案。
4. **函数内内存。** 对每个重点调用先保存 asm/微码/CFG，再运行 analyze 与 trace。核验 trace 的查询点是取 vptr 的 load，最近完整写覆盖旧写；load 后到 call 前的写不能倒改已加载值。核查同根不相交字段、部分覆盖、可能别名、未知/外部调用。历史 prior-store 数量不是到达存储证明，静态全局指针的加载值不当作常量。至少尝试 6 个不同实际调用；若可用实例不足如实报告。
5. **跨函数。** 仅按当前 frontier 少量增补 `export --view flow`。GLBOPT3/LVARS 桥接要求唯一同 EA 调用、相符偏移/实参位置；不能直接等同两边 local index/VN。检验一个已导出直接 callee 的写入/无写路径、一个 caller 实参回溯和一个返回别名路径（实际不存在则保留未覆盖）。未绑定 formal 仍保留外部 caller frontier；allocator、未知返回值、address-of-local 等未解析情况不得硬连。构造/析构阶段只能记录有顺序的存储观察，不证明对象存活、完整生命周期或动态类型。
6. **边界与预算。** 同一调用先用 hops=1/nodes=50/edges=200，再用 hops=3/nodes=200/edges=2000；必要时最多 hops=6/nodes=500/edges=4000，alternatives<=16/context<=4。对照截断原因、路径和未知项，不把较大预算的唯一候选写成运行时唯一目标。循环/递归应终止。`local_memory`、`object_memory`、bridge、targets、index_frontier、phase_observations、local_store_history、lifetime 与 assumptions 都要保存。
7. **缓存、历史、同步。** 相同输入重查应复用 run。选择一个窄函数真实刷新已有视图（即使内容相同），确认旧 trace 失效、普通 show 拒绝、`--include-stale` 能查看历史，重算追加新 run 且旧 JSON 不变。将旧 `vtrace` 绑定 job 并核验 review，重新检查最新证据后追加 revision。重建表/视图改变后不能偷偷复活旧 run。不得直接编辑真实目标观察行来测试 hash；如需人工破坏，仅在单独标注的合成/一次性 fixture 中操作。
8. **CLI/MCP 一致性。** 在同一副本、同一选择器/预算比较 `trace_virtual_call`、`vcall_trace_show` 和 CLI（剔除 cached/时间等非语义字段）。MCP stdio 的 IDA 刷新若失败/超时，记录完整命令、超时、stderr 和受影响项；不得绕过后声称该路径通过。可用 CLI 继续其他独立任务，但分别报告。
9. **关系与类型门控。** RTTI OFF 时关系边缺失应明确说明。对独立证据支持的窄计划测试 type-preview 与过期 revision 拒绝；只有证据充分才在隔离 IDB 上显式 apply，保存逐项结果、同步后的视图和 job review。缺少依据则标记 apply 未执行，不为覆盖率强行改变类型；由已应用类型生成的伪代码不作为其正确性的独立证据。

总增补导出上限先定为 12 个函数，累计最多 24 个，单次 IDA 操作设置有限超时（如 300 秒）。全 clang 反编译、无边界扩展和通过直接改 SQLite 补观察均禁止。任何操作超预算就停止，保存 frontier 和最小下一步。可单独写合成反例验证无实际样本的边界，但与 LLVM 数据/报告严格分开，不能据此填充 LLVM 成功案例或 precision/recall。

## 4. 交付与冻结

本轮目录保存 `deepseek-llvm-vtable-round2-report.md`、全部命令/参数/耗时/退出码、原始 JSON、SQL 核验、job/revision/handoff、函数与调用样例清单、旧/新 run hash，以及原冻结文件前后哈希。

报告提供逐项验收表：通过 / 失败 / 未覆盖，分开“工具结构输出正确”“二进制证据支持”“假设成立但未证实”。列出候选/总间接调用/缺失函数/unknown/partial/truncated/error 的分母，样例含函数 EA、call ID/EA、vptr load block/ordinal、对象/槽偏移、表/slot/raw entry/thunk、跨函数路径和第一 frontier。不要宣称无法取得真值的全库 precision/recall，不用匹配度当概率。

最后只读 SQL 逐条核对报告引用，运行 job-check，未能复核的 claim 保持 review 并解释。冻结报告并生成产物 manifest/SHA-256。本轮结束后也不自行查看 LLVM 源码或首轮源码评估；源码对照由用户随后交给独立评估者。最终回复实际完成项、主要失败/未覆盖和唯一下一最小工作单元，勿把测试意图写成执行成果。
