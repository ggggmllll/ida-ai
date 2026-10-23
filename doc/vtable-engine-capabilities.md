# 虚表引擎首版交付范围

计划状态：**已收尾（2026-10-23）**。P0–P4 有界首版作为当前版本交付，本计划不再追加实现或盲测轮次。以下能力边界随版本保留；真实 C++ 正向恢复验证、通用别名/生命周期及复杂 ABI 扩展转入后续研究，未验证部分不记为通过，也不作为本轮继续执行的待办。

2026-10-23：P0–P4 的有界首版实现和离线验收已交付，并完成 zlib 隔离副本上的真实 IDA 索引、类型应用、同步及重建测试。LLVM 盲测仍未证明真实对象到运行时目标的闭环；真实 C++ 正向验收与首版接口交付分别记录。这里的“完成”指以下支持契约，不表示已求出任意程序的别名、生命周期或全部运行时目标。

| 阶段 | 实现及证据 | 明确保留的边界 |
| --- | --- | --- |
| P0 观察 | SQLite 迁移；GLBOPT3/LVARS 指令、微码 CFG、定义使用定位、截断；已读取数据范围内 loader fixup 元数据与加载字节 | fixup 不等于运行时地址，不解码任意重定位；缺失 API、范围、大小和预算均报告 |
| P1 表 | Itanium 地址点/槽位候选、有限 RTTI 描述符、分类、组合反查；最多 32 边的 IDA thunk 链，保存原入口及终止原因 | 无 RTTI 时不确认类身份；thunk 的 this/返回调整未知；相对槽编码、MSVC、VTT 等不支持 |
| P2 函数内 | 双加载调用模式及 v6 先从字段取 receiver 指针、再取 vptr/常量槽的模式；唯一实参 identity 绑定；在取 vptr 的程序点逆向查询最近完整存储；分支保留替代项，同根不相交字段跳过，部分覆盖和可能别名写入形成 frontier | receiver 指针字段偏移与 receiver-relative vptr 偏移分开；prior-store 计数只表示历史；不同局部变量不证明不别名；不以静态全局指针快照代替运行时值 |
| P3 跨函数 | 独立匹配两 maturity 的唯一同 EA 调用/偏移/实参位置；LVARS 已导出的直接调用实参/形参、callee 出口存储、绑定上下文的返回别名；有界 caller 查询 | 不跨 maturity 等同 VN/local index；结构对应是假设；未绑定入口保留外部 caller；未知分配/外部调用、递归、截断停止 |
| P4 应用 | 有来源的类关系候选；AI 提供类型计划，preview/revision token/逐项 apply；同步与 job review | 不自动建立完整类层次；应用可部分成功，无跨 IDB/SQLite 原子事务 |

`vcall-analyze` 保留兼容目标列表及历史计数，同时增加 `resolution.local_memory`；以 `vcall-trace` 获取独立、可复查的跨函数结果。`vcall-trace-show` 重新校验来源，历史输出须显式允许 stale。CLI/MCP 复用同一服务，每个 CLI 命令有独立 skill。

追踪预算为 hops/nodes/edges/alternatives/context；循环和未知路径不会因另一路成功而消失。`unique_under_assumptions` 仅表示模型内收敛；总结果仍为 `completeness: partial`、`runtime_reachability_proven: false`。程序点存储和同块历史可供 AI 研究构造/析构阶段，但工具不自动赋予阶段名称，也不证明对象存活、存储复用或分配所有权。

来源 hash 包含实际指令、CFG、合同、表槽及 fixup 观察；不能只依赖摘要 content_hash。任一相关微码刷新保守失效全部 trace；重建、reset 保留历史但标记 stale。相同内容在显式失效后重算会追加 run，不覆盖旧 JSON。job 可引用 `vtrace:<run_id>`，失效后进入复核。搜索加速缓存仍与这些正式分析记录分离。

离线回归覆盖覆盖写/别名/部分写、跨分支、只读与未知调用、返回别名、外部 caller、循环和预算、桥接不一致、原始行变化、历史不可变、job 指纹、fixup 缺失/失败、thunk 多跳/循环/断链，以及 loaded-pointer receiver 的正反模式。通用别名/生命周期求解、复杂 ABI 和跨构建匹配属于后续研究，不能用首版候选替代其证明。

本轮验证：`python -m unittest discover -s tests -q` 共 135 项，132 通过、3 项集成测试跳过。额外手动运行真实 IDA 9.1（无界面），仅使用 stripped ARM64 zlib；原始二进制、DB、IDB 保持原哈希，所有操作在本地忽略的副本内进行。

| 验收项 | 直接运行的结果 | 结论范围 |
| --- | --- | --- |
| 表与 fixup 观察 | 180 个指针观察、75 个扫描范围内 fixup、2 个 heuristic 候选、48 个槽、0 RTTI descriptor，无扫描截断 | 普通函数指针序列也可成为候选；不确认 C++ 表 |
| 全函数微码与调用索引 | 206 个函数，185 成功、21 个导入桩失败；12 个间接调用，全部 unknown；0 vptr write | 失败留在覆盖分母；此负对照不验证真实 loaded-pointer 正例 |
| 单点 analyze 与类关系 | unknown / pattern_incomplete、0 兼容目标、0 类关系 | 不虚构 receiver、目标或类身份 |
| preview → apply → SQL 同步 | 第二份独立副本注册通用双指针记录，在 0x1C098 应用记录值类型；revision 校验及 IDA 写入成功，同步后 3 个定义 / 2 个赋型 | 仅验证通用数据布局的应用机制，不宣称恢复 C++ 类 |
| 应用后失效与重建 | 旧 run stale、父 job claim 进入 review；真实 IDA 重建仍为 2/48 表候选/槽、12 unknown、0 vptr write；新子 job 单独记账 | 保留旧证据和 review，不自动复活旧 claim；类型依赖伪代码不当独立证明 |

本地证据在 `agent_reports/deepseek-zlib-round6/` 和 `agent_reports/deepseek-zlib-round6-type-apply/`，不提交分析库或报告。未在本轮重跑 LLVM 或 MCP 内的 IDA 派生进程；不能把 CLI 的 IDA 成功等同于该 MCP 路径成功。

用户提供的 LLVM round2/4/5 报告显示：round4 的单函数产生 216 个 unknown；round5 的单函数产生 246 个 site，其中 1 个结构候选、245 个 unknown，单次 analyze 只有宽泛兼容集合且停在 `object_identity_unresolved`。round5 唯一候选的 basis 仍为双加载分支，不能据此声称真实 v6 loaded-pointer 分支已经验收。后续正向实验应优先验证一条有独立依据的 receiver → reaching vptr store → address point → slot 链；没有这条证据时保留 partial，不用同槽位兼容目标数量替代目标解析。
