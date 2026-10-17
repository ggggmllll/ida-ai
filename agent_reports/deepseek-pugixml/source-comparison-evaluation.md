# DeepSeek pugixml 盲测源码对照评估

评估对象：`deepseek-pugixml-type-recovery-report.md` 及其本地数据库导出。<br>
对照目标：`D:\IDA Scripts\targets\pugixml\src\pugixml.cpp`、`pugixml.hpp`，构建为 Android AArch64、Release、`PUGIXML_COMPACT=OFF`、`PUGIXML_WCHAR_MODE=OFF`。<br>
本评估只读了现有源码、报告、SQLite 数据库和实验产物；没有重新运行 IDA、刷新数据库或重新执行实验。

## 总体判断

这次结果对“从局部反汇编和伪代码恢复对象布局”的表现较强：节点字段偏移、节点/属性对象的管理尺寸、解析结果布局，以及 child 链表的头尾关系均与源码吻合。混合宽度访问能按 base 来源区分 header、字符串内容、writer 和 allocator page，避免了把同一数值偏移直接解释成 union，这是本次最有价值的分析结果。

结果仍是小范围的类型恢复实验，不等同于恢复出可编译、功能等价的源代码。实验只为少量重点函数导出了视图；传播仅接受少数 identity/参数关系，且在 hop 上限处截断；没有将类型应用回 IDB。报告保留若干未知项是合理的，但其中有些未知项其实可从目标源码直接确认。

## 源码对照结果

| 项目 | 评估 | 源码对照 |
| --- | --- | --- |
| `load_buffer_impl` 返回与参数 | 符合 | 数据库中 `xml_document::load_buffer` 的调用点先将 wrapper 的 X8 保存为结果地址，再将该地址放入 X0 调用 helper；helper 的参数寄存器和栈参数与报告顺序一致。源码返回 `xml_parse_result`，结果字段位于 `status +0`、`offset +8`、`encoding +0x10`，总尺寸为 0x18。 |
| 节点结构 | 符合，报告的下界判断偏保守 | 源码字段依次为 `header/name/value/parent/first_child/prev_sibling_c/next_sibling/first_attribute`，偏移为 `0x00/08/10/18/20/28/30/38`，本构建尺寸恰为 0x40。报告的 0x40 管理尺寸证据正确，但“仅能证明下界”的措辞弱于源码已能确认的精确尺寸。 |
| child 链表尾指针 | 报告中的 hypothesis 得到确认 | `append_node` 在空链表时令首节点的 `prev_sibling_c` 指向自身；非空时把新尾节点写入 `head->prev_sibling_c`。因此非空链表的 `first_child->prev_sibling_c` 是尾节点，`next_sibling` 沿正向链遍历。报告对 `append_child` 的下一步验证建议是正确且最小的验证方向，但源码对照已经回答了这个问题。 |
| 属性结构 | 部分符合，遗漏一个字段 | 源码布局为 `header/name/value/prev_attribute_c/next_attribute`，偏移 `0x00/08/10/18/20`，尺寸 0x28。报告正确识别 `+0x20` 为 next 和 0x28 的管理尺寸；`+0x18` 不是未知保留字，而是 `prev_attribute_c`。本次选定的函数视图没有覆盖属性插入/移除 helper，属于分析范围造成的保守遗漏。属性链表也将尾节点放在 `first_attribute->prev_attribute_c`。 |
| Header 低位标志 | 有一处字段映射写反，且说明不完整 | 源码定义 type mask=`0x0f`、value allocated=`0x10`、name allocated=`0x20`、contents shared=`0x40`。报告第 5.1 节把 `0x10/0x20` 按 name/value 顺序写，顺序相反；第 9 节的注释“value/name”则是正确的，报告内部不一致。`0x40` 的 shared 标志未进入字段解释。 |
| Header 高位 | 未恢复 | 非 compact 构建通过 `((object - page) << 8) | flags` 生成 header，并以 `header >> 8` 还原对象到 page 的偏移。故 header 除 type/状态位外，还承载 page 定位信息，不能只视为普通标志整数。 |
| 字符串所有权与 parser 路径 | 结论方向正确，开放问题可由源码关闭 | `parse_tree` 直接将 name/value 指向可修改的 parse buffer，parser 创建节点/属性时 header 标志初始化为零，解析赋值本身不设置 allocated 位。相反，`strcpy_insitu` 新分配字符串后才设置对应的 name/value allocated 位；析构路径依据这些位释放字符串。普通 `load_buffer` 会准备私有可写 buffer，in-place 接口则使用调用方 buffer，所以 parser 字符串的 backing storage 生命周期由文档 buffer/API 路径管理，不是每个字符串前都带单独的 4-byte 分配头。 |
| 字符串分配前缀 | 布局正确，语义可进一步确定 | payload 紧跟 4-byte `xml_memory_string_header`；对于输入长度 `len`，`strcpy_insitu` 传入 `len+1`（含终止符），再按 8-byte block 对齐，得到报告中的 `(len + 12) & ~7`。两个 16-bit 字段分别是相对 `page->data` 的 `page_offset` 和 `full_size`；两者均以对齐 block 为单位，`full_size==0` 表示字符串占用整页。报告的“语义未证明”是合理的盲测保留，但源码可以完整确认。 |
| `xml_parse_result.offset` 类型 | 宽度符合，符号性不符合 | 源码将 `offset` 声明为有符号 `ptrdiff_t`。报告候选声明写成 `u64`，AArch64 下尺寸/偏移正确，但符号性错误或至少未恢复。 |

## 工具与分析过程的表现

- **利用形式扫描：** 24 次扫描均成功只证明请求的函数视图可用，不等同于扫描对全库有覆盖。报告明确指出 `score=1.00` 只表示 form 约束满足，这个解释是正确的。对 `node_output` 的混合宽度结果，按 operand base 区分节点、payload、writer buffer，确实避免了把宽度混用误判成 union；但判断仍由人工阅读 microcode 完成，不能从这些成功扫描数推出语义分类器的精确率或召回率。
- **传播：** 4 个被接受的 proposal 只确认了局部 identity/参数关联。5 个 conflict、12 个 unresolved、10 个间接调用和 `max_hops=3` 截断都被保留，报告没有把传播不到解释成“没有引用”，这是合适的证据纪律。单个 seed 和受限视图不足以证明全局类型传播效果。
- **证据核验：** 报告引用的 31 个指令地址有 SQL 行核对，另有 microcode/nested-width 核对文件；这支撑报告中局部指令描述的可追溯性。源码评估确认的漏项（属性 prev、header 高位及分配记录单位）主要是视图/范围没有覆盖的语义，不是已列 SQL 地址本身错误。
- **变更风险：** 没有应用 IDB 类型，避免了在字段语义未充分确认时产生误导性伪代码。job claim、截断 frontier 与 revision 历史也按报告所述保留；这使后续回头修正有可追踪依据。

## 对盲测结论的归纳

该实验已经从无类型输入中恢复了主要对象图和关键数据流约束，特别是 0x40 节点布局、child 尾指针惯例、`load_buffer_impl` 参数关系和字符串分配路径。源码对照没有推翻这些主结论。

主要差距是 header 被当作“标志字段”解释得不够完整、name/value 分配位在报告一处顺序颠倒，以及报告未从未选中的属性链表 helper 和 parser 直接赋值处补齐 `+0x18`、parser ownership 与字符串 header 单位。`xml_parse_result.offset` 的候选 C 声明还丢失了 signedness。除了这些需更正/补充之处，剩余的 indirect-call 与大范围传播不确定性仍属于当前覆盖边界，不应通过源码对照把它们算作盲测已经恢复的事实。

## 对照位置

- `pugixml.cpp:482-502`：header masks 与 page-offset 编码/解码。
- `pugixml.cpp:550-554, 686-736`：字符串记录和分配/释放单位。
- `pugixml.cpp:1143-1178, 1240-1269`：普通指针布局、构造及析构。
- `pugixml.cpp:1300-1322, 1399-1422`：节点与属性链表追加规则。
- `pugixml.cpp:2439-2485`：insitu 字符串更新及 ownership flag。
- `pugixml.cpp:3327-3391, 3534-3557`：parser 对节点/属性字符串的直接赋值。
- `pugixml.cpp:4841-4884, 7871-7889`：输入 buffer 的转换、保留和 load 接口模式。
- `pugixml.hpp:1105-1114`：`xml_parse_result` 字段类型。
- `build-ai-stripped-android-arm64-v8a/CMakeCache.txt:303,328`：本构建的 compact/wchar 选项。
