# 虚表引擎首版交付范围

2026-10-21：P0–P4 的有界实现和离线验收已交付；LLVM 第二轮真实 IDA 验收交给独立盲测。这里的“完成”指以下支持契约，不表示已求出任意程序的别名、生命周期或全部运行时目标。

| 阶段 | 实现及证据 | 明确保留的边界 |
| --- | --- | --- |
| P0 观察 | SQLite 迁移；GLBOPT3/LVARS 指令、微码 CFG、定义使用定位、截断；已读取数据范围内 loader fixup 元数据与加载字节 | fixup 不等于运行时地址，不解码任意重定位；缺失 API、范围、大小和预算均报告 |
| P1 表 | Itanium 地址点/槽位候选、有限 RTTI 描述符、分类、组合反查；最多 32 边的 IDA thunk 链，保存原入口及终止原因 | 无 RTTI 时不确认类身份；thunk 的 this/返回调整未知；相对槽编码、MSVC、VTT 等不支持 |
| P2 函数内 | 双加载调用模式；在取 vptr 的程序点逆向查询最近完整存储；分支保留替代项，同根不相交字段跳过，部分覆盖和可能别名写入形成 frontier | prior-store 计数只表示历史；不同局部变量不证明不别名；不以静态全局指针快照代替运行时值 |
| P3 跨函数 | 独立匹配两 maturity 的唯一同 EA 调用/偏移/实参位置；LVARS 已导出的直接调用实参/形参、callee 出口存储、绑定上下文的返回别名；有界 caller 查询 | 不跨 maturity 等同 VN/local index；结构对应是假设；未绑定入口保留外部 caller；未知分配/外部调用、递归、截断停止 |
| P4 应用 | 有来源的类关系候选；AI 提供类型计划，preview/revision token/逐项 apply；同步与 job review | 不自动建立完整类层次；应用可部分成功，无跨 IDB/SQLite 原子事务 |

`vcall-analyze` 保留兼容目标列表及历史计数，同时增加 `resolution.local_memory`；以 `vcall-trace` 获取独立、可复查的跨函数结果。`vcall-trace-show` 重新校验来源，历史输出须显式允许 stale。CLI/MCP 复用同一服务，每个 CLI 命令有独立 skill。

追踪预算为 hops/nodes/edges/alternatives/context；循环和未知路径不会因另一路成功而消失。`unique_under_assumptions` 仅表示模型内收敛；总结果仍为 `completeness: partial`、`runtime_reachability_proven: false`。程序点存储和同块历史可供 AI 研究构造/析构阶段，但工具不自动赋予阶段名称，也不证明对象存活、存储复用或分配所有权。

来源 hash 包含实际指令、CFG、合同、表槽及 fixup 观察；不能只依赖摘要 content_hash。任一相关微码刷新保守失效全部 trace；重建、reset 保留历史但标记 stale。相同内容在显式失效后重算会追加 run，不覆盖旧 JSON。job 可引用 `vtrace:<run_id>`，失效后进入复核。搜索加速缓存仍与这些正式分析记录分离。

离线回归覆盖覆盖写/别名/部分写、跨分支、只读与未知调用、返回别名、外部 caller、循环和预算、桥接不一致、原始行变化、历史不可变、job 指纹、fixup 缺失/失败、thunk 多跳/循环/断链。真实 LLVM 第二轮按 [独立提示词](deepseek-llvm-vtable-round2-test-prompt.md) 执行，未运行的真实 IDA 路径不能写作通过。通用别名/生命周期求解、复杂 ABI 和跨构建匹配属于后续研究，不能用首版候选替代其证明。

本轮验证：`python -m unittest discover -s tests -q` 共 132 项，129 通过、3 项真实 IDA 集成跳过；Python 编译检查及本轮新增/受影响 skills 校验通过。未在本轮重跑 LLVM 的真实 IDA 观察提取、类型应用或 MCP 内 IDA 派生进程。
