# libg 协议分析中的 ida-ai 使用问题

本次目标是用真实协议分析检验工具，协议恢复结论为辅助产物。使用用户提供的 `D:\libg_fixed.so.i64`，只在复制的 IDB 上做离线分析。完整命令、耗时、失败日志、观察与 job 历史保存在本地忽略的 `agent_reports/libg-protocol-20261023/`，不提交目标文件或反编译文本。

状态：第一轮有界试用已记录，协议分析未完成。问题区分“实际遇到”“代码审查发现但尚未影响任务”和“未验证建议”；不将未使用的功能一概判为失效。此次目标以用户明确指定的 libg 为准，取代旧本地说明中的 zlib 样本限定。

| 编号 | 状态 | 问题与证据 | 本次绕行 | 改进目标 |
| --- | --- | --- | --- | --- |
| GAP-001 | 实际遇到 | 用户只提供已有 IDB；`init` CLI 与 skill 只公开从 `--binary` 建库，没有明确的已有 IDB 接入方式 | 检查内部实现，复制 IDB，以内部 `connect/set_metadata` 设置路径，再运行 CLI `sync`；细节见 preflight 与 bootstrap 脚本 | 提供已有 IDB 的接入入口，明确复制/复用方式、原始二进制缺失的支持边界 |
| GAP-002 | 实际遇到（字符串）；导入链原因待查 | `symbols` 没有字符串正文。`aCannotSendNull` 引到 `0x8ABBCC`，反编译才知道正文是聊天表情专用的 “Cannot send null emote in chat.”，不是通用网络发送错误；网络导入符号存在，但直接 xref 与 `.plt` 函数查询均为空，不能据此断言无调用 | 符号+xref 定位后逐函数反编译；导入链异常保持未决，未归咎导出器 | 有界字符串正文/编码/xref 快照；导入→GOT/PLT→调用者导航及数据质量诊断 |
| GAP-003 | 实际遇到 | 初次 `sync` 成功耗时 214.235 秒，导出 70,033 函数、5,496,076 xref、782,502 基本块；运行期间 CLI 没有阶段进度 | 查看 IDA 进程 CPU 判断是否仍工作；没有将等待误报为挂死 | 阶段、计数、耗时的结构化进度，stdout 最终 JSON 与 stderr 进度分离 |
| GAP-004 | 已复现缺陷，优先修复 | `0xAE3E4C` 的 GLBOPT3 微码 block 2 / ordinal 0 是 `mov(icall(...), x0)`，间接调用 EA=`0xAE3EA0`；原始指令为 `BR X4`，但 `vcall-build` 返回 `site_count=0/status=ok`。`virtual_tables.py` 的调用枚举只接受顶层 `opcode == icall`，跳过嵌套调用 | 人工查询 operand JSON，再对照 disassembly；未修改检测器，也未把缺失站点伪装成候选 | 递归枚举嵌套调用，保存 operand path 并去重；同时审计 analyze/trace 的调用定位契约，补此真实微码形态的回归测试；结构无法解析也应保留 unknown 站点 |
| GAP-005 | 实际遇到，选择语义/预算问题 | `export pseudocode --range 0x12282A8 0x12282F8`（80 字节）导出 100 函数；函数主范围仅 4 个，但 CFG 有 100 个所属函数与之重叠，符合当前选择规则。不是未经核验的错导出结论 | SQL 对比主范围与基本块所属函数；本次 5.031 秒成功，但无法事先从 CLI 获知扩展数量 | 只读 selection preview，列出 entry/body/shared-tail 命中原因；增加 max-functions 上限，并提供多地址显式选择 |
| GAP-006 | 实际使用成本 | 跨散布地址的按需导出须逐次启动 IDA；本轮单函数伪代码导出约 4.0–4.2 秒，普通 CLI 没有多地址、多视图的一次性导出入口 | 连续运行两个单函数命令；不把正常启动成本夸大为阻断 | 显式地址列表与多视图批处理，维持每函数状态和范围预算 |

每个确认问题保留触发条件、原命令、错误/实际行为、额外成本及临时绕行。后续工具修复另行提交；本轮不通过预先修工具来隐藏试用摩擦。

第一轮有界路径：聊天表情入口 `0x8ABBCC` → 构造 `0x10469C4` → 入队 `0xADB934`；构造函数写入 `0x18B3230`。有界扫描 224 字节得到 4 个代码指针序列候选、22 个 slot，RTTI 和 ABI 表边界均未确认，工具正确保留 unresolved。该对象对应槽位函数分别返回 15687 和 11；它们作为消息 ID/版本的语义仍是假设。疑似编解码函数通过内嵌对象 `+8` 的虚方法，成对传出/接收对象 `+144/+148` 的两个 32 位字段；尚未确认线上的宽度、字节序、包头或加密流程。

局部成功不能掩盖缺陷：单函数导出、SQL 和有界表扫描都能帮助推进，但调用枚举已漏掉一个已导出的嵌套 `icall`。后续优先修 GAP-004，再接入现有 IDB 与字符串发现；不以增加反编译数量代替修复入口信息和覆盖统计。

复现日志：`01-sync.json`、`08-string-xrefs.json`、`12-send-text.json`、`20-small-vcall-build.json`、`22-microcode-text.json`、`25-slot-and-asm.json`、`27-base-message.json`、`32-range-diagnostics.json`、`34-shared-tail-scope.json`。完整命令及输出保留于忽略的实验目录；不提交游戏反编译代码。

本轮检查：SQLite `quick_check=ok`；job 1/2 均追加 revision 和 handoff，`job-check` 无待复核项。原始 IDB SHA-256 复核保持 `0B9E824B0C739340D292239E3CCA7A43D52FDDC3C24457FEC82D388178205212`。job 保持 active，明确下一步及停止条件，不把尚未完成的协议任务标成 done。本轮只新增文档和本地实验产物，没有改动工具实现。


## 工具修复回测（2026-10-23）

本次按用户要求修复工具，并验证共享消息虚表槽位的批量定位办法。保留原始问题与旧 run；本轮未扩大协议语义结论。

| 问题 | 修复 | 回测和边界 |
| --- | --- | --- |
| GAP-001 | attach-idb 默认复制已有 IDB，缺少原始 binary 也可同步；显式 reuse 才复用源 | 测试覆盖复制、冲突与拒绝覆盖；未额外重跑全量 libg 接入 |
| GAP-002 | discover 将字符串正文和导入写入 SQLite；import-callers 有界追踪已导出反向引用并报告缺失链接 | 实测 30,519 字符串、473 导入，找到聊天表情错误全文。四个网络导入仍没有 IDA 直接 xref，工具明确返回 frontier，底层 IDB 缺失链接的原因仍未解决 |
| GAP-003 | stderr JSON 阶段/计数进度和 15 秒心跳，stdout 保留最终 JSON | 批量导出和发现实测观察到进度；测试覆盖半行和去重；未另做一次 214 秒 sync |
| GAP-004 | 嵌套调用递归枚举，保存 operand path；trace bridge 同步支持 | 提交 69727b9；相同微码离线重建从 0 站点变为 1 站点、1 结构候选 |
| GAP-005 | export 增加 preview、max-functions、addresses；MCP 同样提供预算与预览 | 原 80 字节范围预览返回 100 函数，区分入口、主范围和 CFG 重叠；超预算在启动 IDA 前拒绝 |
| GAP-006 | export batch 多地址、多视图一次启动 IDA，保留每视图状态 | 两函数的汇编和伪代码共四份视图全部 ok，一次启动 4.750 秒 |

新增 vtable-match：JSON 中按字节偏移定义 exact/function/null 槽位，未声明偏移为通配。至少一个非零 exact 锚点；先用加载后原始指针索引定位，再逐槽位 AND 核验。不依赖 RTTI 或已有虚表边界。扫描、结果与锚点均有预算；返回覆盖信息；刷新使旧指针输入的虚表/调用派生数据 stale。MCP match_vtable_structure 提供同一 matcher 的离线入口。

libg 实测以 +0x30 等于 0x12282E8 为锚点，要求 +0,+8,+0x10,+0x18,+0x20,+0x28,+0x38 均为 IDA 函数入口指针：得到 **348 个结构候选**，包含已知 0x18B3230；核验 348 个锚点，结果未截断。扫描可读、非执行、非 BSS 段中加载字节 2,284,420。辅助 fixup 枚举达到 100,000 条预算，已显式标记 truncated；本次 raw-pointer 匹配不依赖 fixup 重定位推理。348 个候选不等于 348 种已确认消息，也不证明运行时可达性。

验证：141 项测试，3 项按环境条件跳过；最后新增 MCP 接口后单独复跑 MCP 两项测试通过。新增命令各有独立 skill。完整命令、stdout/stderr 与耗时保留在忽略目录日志 fix01-nested-index 至 fix06-import-callers。实验 IDB/SQLite/脚本及反编译内容不提交。
