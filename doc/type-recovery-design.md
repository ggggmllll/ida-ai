# Type recovery tooling design

## Implementation status

Implemented: structured microcode export at MMAT_GLBOPT3 and JSON utilization-form scanning through `type-scan`. Results are location candidates, with weighted constraint satisfaction, missing observations, conflicts and source hashes. Nested expression scanning and bounded ordered sequences are supported. Offset-constrained scans also return a bounded access profile retaining every observed width, direction and sample location at each requested numeric offset, including widths filtered out of the candidate list. This is an instruction/expression search, not an object identity classifier.

Not implemented: logical-object graphs, alias analysis, layout revision storage, object-level matching and scan acceleration caches. Existing byte-search caches remain separate. The current access profiles are diagnostic output, not a persisted object/field model: same-offset observations remain separate until alias and base identity are established. The design below describes these future engineering goals; it does not advertise callable tools.

## Product goal

Help the AI maintain and revise type hypotheses from concrete usage evidence. The system should expose where and how an object is used, propagate only confirmed constraints with explicit provenance, and find other objects or call sites whose observed usage is compatible. The AI remains responsible for choosing a type and applying it through the existing type MCP operations. Do not make a one-click type guesser or silently overwrite IDA types.

The workflow is:

`raw observation → normalized usage feature → constraint → explained candidate → AI decision → IDA type edit → refreshed observations`

Each step must keep its source revision and dependencies. Typed pseudocode generated after an edit is useful feedback, but it is not independent proof of the type that produced it.

## Usage evidence and object model

Microcode usage extraction is a prerequisite. Keep disassembly, pseudocode, and microcode as separately versioned views, and identify which view and Hex-Rays state produced every feature. A feature should point back to the function, instruction or microcode location, operand/value flow, and relevant path or call context.

Model globals, stack/local objects, parameters, returns, call arguments, and derived memory objects as logical objects. Record aliases and transformations such as assignment, load/store, address-taking, pointer arithmetic, pass-to-call, return, and offset adjustment. Preserve uncertainty about object base and aliasing rather than forcing every memory access into a field immediately.

Normalize observations such as read/write/read-modify-write, access width, offset, alignment, stride, masks and bit operations, comparisons and branches, arithmetic, API/calling-convention use, and observed lifetime or storage reuse. Each fact should retain the raw locations that support it and a dependency group so repeated instructions from one expression do not masquerade as independent evidence.

## Constraints and ambiguous layouts

Represent facts as constraints with a source, scope, confidence class, and status such as observed, derived, disputed, or superseded. Propagation should create bounded proposals with a trace of every edge and transformation. Stop and report conflicts when incompatible confirmed constraints meet; do not recursively overwrite declarations or choose a convenient winner.

Treat access extent as a lower bound unless object boundaries are independently established. An access reaching byte `c` means the observed object view covers at least that range; it does not prove `sizeof(type) == c`. An apparent `long` access and two `int` accesses may be overlapping union/reinterpretation views. Preserve both views and their contexts.

Equal widths do not distinguish integer, floating-point, or pointer-like values. A stride does not prove array-versus-pointer source syntax. Identical offsets do not distinguish structures that share a prefix. If evidence cannot discriminate, return the remaining alternatives and name the next useful observation or call site to inspect.

Represent uncertain access width, sign extension, object base, path reachability, and alias as uncertainty, not as an invented exact field. Model storage reuse and mutually exclusive union views separately from simultaneous fields. Arrays, nested objects, bitfields, unions, and opaque byte regions should remain candidate layouts until enough evidence exists to distinguish them.

## Candidate matching and confidence

Separate three results:

- **Compatibility:** whether a candidate can explain the observed constraints under stated assumptions.
- **Coverage:** which distinct observed constraint groups the candidate explains, and which remain unknown.
- **Identity:** whether evidence actually establishes that the binary's original source type was this declaration. In most stripped binaries, usage evidence alone cannot prove identity.

Do not emit a probability that is not calibrated against held-out data. Prefer a reproducible result vector: hard conflicts, satisfied constraint groups, unexplained groups, unknowns, assumptions (such as a union view), and independent evidence sources. If a single score is useful for sorting, document its feature groups and weights, cap repeated evidence within one group, and show the full vector beside it.

“100% match” may mean only that every currently observed constraint is compatible with the candidate under the listed assumptions. It must not be presented as 100% probability of the source type. Unknown or unobserved layout regions do not count as confirmed matches. Identical-prefix candidates should remain tied until a discriminating use is found.

For example, group observations into offset/width access (weight 3), pointer dereference (3), arithmetic or mask usage (2), and call-boundary contract (2). Define coverage as satisfied group weight divided by total observed group weight; unknown groups stay in the denominator. A candidate explaining the first three groups scores 8/10 coverage with an unknown call contract, even if those accesses occur in 100 instructions. A verified incompatible call contract is a conflict, not just a two-point deduction: report the contradiction and withhold a compatible label. Two candidates with 10/10 coverage can still be indistinguishable if only their common prefix was observed. These initial weights are a documented ranking heuristic, to be evaluated on held-out samples rather than interpreted as a probability.

Expose proposed capabilities separately: inspect object features; explain one constraint and its provenance; preview bounded propagation; compare candidate layouts against an object; find compatible objects; inspect layout revision differences. Each response should include source revision IDs, conflicts, unknowns, and the next discriminating observation. These are capability goals, not callable command names.

Use examples to request the next evidence: a write to an otherwise read-only region may distinguish mutability; a call boundary may reveal a required pointer or length; a branch on a masked value may suggest flags; a later access beyond the proposed end may increase the minimum observed extent. Present each as an experiment, not as a fact.

## Evolving type revisions and cache boundaries

Type layouts change during real analysis. Give logical objects stable IDs and version their proposed layouts. Field IDs should not be derived only from offsets, because fields may split, merge, move, or change type. Record explicit field correspondence when a layout revision changes partitioning. Keep the reasoning lineage of an old type decision even if the declaration is later revised.

Use immutable logical-type and layout revision IDs, separate from IDA display names and type ordinals. An application decision pins the chosen layout revision and target object revision. A later split/merge or size change produces a new revision and an impact preview; it does not silently reinterpret old observations. Until dependencies can be tracked precisely, invalidate conservatively and label the broader review scope. The current type_definitions/type_assignments tables track tool-mediated declarations, not a complete external IDA type-library snapshot.

Store durable observations and type decisions in the analysis/job history with their source revisions. Keep only recomputable scan acceleration in a separate cache, never as an AI-queryable substitute database. Cache keys should include binary/IDB identity, function and address scope, IDA/Hex-Rays version, microcode maturity and options, and relevant type-state revision. Invalidate derived features when any dependency changes.

Connect type reasoning to jobs: conclusions cite feature evidence and upstream claims; a revised type marks only dependent observations and conclusions for review where dependencies are known. Use job handoffs to preserve the next experiment and stop condition so a long A→E investigation resumes at its current branch rather than replaying old detail.

## Implementation order and evaluation

1. Export microcode with stable function/location identity and explicit decompilation status.
2. Extract and cache normalized usage observations while persisting their provenance and cache dependencies.
3. Add object/alias graphs and constraint propagation with bounded traversal, conflict explanations, and alternative views.
4. Add candidate compatibility search with the result vector above and suggestions for discriminating evidence.
5. Let the AI choose a declaration and use existing MCP register/apply operations; then refresh dependent IDA views and mark stale job evidence for review.

Use only the zlib sample for the current implementation phase. For evaluation, keep source-derived labels out of the model-facing evidence and use them as held-out validation. Measure usage-feature correctness, constraint propagation, candidate compatibility, and functional equivalence separately from exact recovery of original names or type spellings. Equivalent layouts and source types may differ while preserving behavior.

## Current utilization search contract

The executable entry points are `export microcode` and `type-scan`; their separate skills describe selection flags and the JSON form. The scanner currently supports opcode, indirect read/write width and immediate-base offset, operand storage category, syntactic dereference depth, bitwise constants, integer constants, calls, returns, extensions and comparisons. Conditions may target one expression or a bounded ordered sequence in one block. A dynamic program selects the sequence combination with the greatest satisfied weight.

Every candidate returns a location, source hash, weighted score, satisfied conditions, unknowns and conflicts. Features in a form are user-specified constraints, not automatically independent evidence groups. Repeating a constraint repeats its weight. Current scores must not be described as the object-level, grouped confidence model proposed above. Object identity, per-object aggregation and data-flow binding are future work. A union, common prefix or larger-than-observed allocation therefore remains ambiguous even with an exact expression match.

The persisted microcode is a real exported analysis artifact, not an acceleration cache. Future feature indexes must be recomputable and separate from the AI-facing SQLite tables; keys must include extraction version and source hashes. At present scans do not persist search records or a feature cache. `--no-refresh` explicitly accepts the existing snapshot; it cannot detect unsaved GUI edits.

## Propagation engineering contract (planned)

The propagator transports a confirmed constraint with its assumptions and provenance. It does not transport an entire guessed declaration merely because two expressions look similar. Matching locates hypotheses; propagation requires a justified relationship. The preview should distinguish observed relationships, derived relationships and speculative edges.

### Endpoints and observations

An endpoint identifies a binary, function (if applicable), logical object, view revision, and projection: pointer depth, byte displacement, extent and optional field/view identity. Endpoints cover global storage, stack storage, function parameters, a function return, actual call arguments and call results. Register numbers and Hex-Rays local indices are only revision-scoped locators. Across revisions, remap with raw address/definition/storage evidence; ambiguous remapping requires review rather than silently reusing a local index.

An observation records function/block/instruction/operand path, source microcode hash, maturity, IDA/Hex-Rays version, object/base uncertainty and extraction rule version. Relationships retain their exact supporting observations. IDA xrefs alone locate uses of an address; they do not prove value equivalence, aliasing, parameter correspondence or a type contract.

### The three edge families

| Family | Required edges and transforms | Direction and stopping rules |
| --- | --- | --- |
| Reference/value | Assignment, address-of, load, store, alias, constant pointer adjustment and derived subobject view | Assignment can convey value constraints, not equality of storage objects. Address-of changes pointer depth; a constant offset changes the projected region. A store connects a value to memory at a specific program point, not every load forever. Unknown stores, lifetime reuse and unresolved aliases stop definite propagation and create a bounded alternative. |
| Parameter | Actual argument at one call site ↔ callee formal argument, mapped by recovered prototype/calling convention and operand evidence | Caller observations can propose a callee requirement; a confirmed formal contract can constrain actuals at other sites. Keep sites separate until their contexts agree. Unknown conventions, missing prototypes, varargs, truncation, indirect call targets and wrappers require explicit mappings or an uncertain edge. |
| Return | Callee return expression → formal return ↔ call-result value → caller consumers | Keep return alternatives/path conditions. A caller consuming a result as a pointer does not prove that every return path is a valid object pointer. A confirmed return contract may constrain result uses; reverse inference remains a proposal until return paths and conventions are checked. Preserve hidden structure-return arguments and ABI lowering explicitly. |

Each transform must describe what survives: bit width, signed/zero extension, byte displacement, pointer level, minimum extent and applicable path. Truncation must not carry the original full-width constraint. Unknown pointer arithmetic must not fabricate a field offset. Passing `&object.field` propagates a subobject view, not the containing layout unchanged. Copying a struct value does not prove pointer aliasing.

Confirmed constraints can include an observed access or an analyst-confirmed semantic requirement. Store these separately: a 4-byte read is an observation; “this is a signed counter” is a claim. Propagating the latter must cite that claim revision. Union alternatives and overlapping views stay distinct and can travel with context instead of becoming simultaneously asserted fields.

### Preview, accept, revise

The future request should pin a seed constraint/claim revision, endpoint revision, allowed edge families/directions, call-site context, maximum hops, node/edge budget and stop policy. A preview returns proposals only: destination, transformed constraint, complete predecessor trace, source revisions, assumptions, competing alternatives, conflicts, unresolved edges and budget truncation. “No more results” must distinguish fixed-point completion from budget exhaustion.

Accepting selected proposals records new derived constraints and job revisions. It must recheck all source revisions against the preview; reject stale previews rather than apply to a changed layout. Acceptance changes reasoning state, not IDA declarations. The AI separately chooses a type registration/application using existing MCP operations, after which normal synchronization regenerates dependent views. Applying one proposal must not implicitly accept every branch of a speculative alias or indirect call.

Conflicts stop the affected branch and return the two incompatible constraints with their traces. Other independent branches may complete. Contradiction is not resolved by averaging a score or overwriting whichever constraint arrived first. Repeated proof through multiple edges must not count as independent confirmation.

### Termination and revisions

Use a worklist and a visited key containing endpoint revision, normalized constraint, context and transform state. Propagate only genuinely new information. Deduplicate equivalent predecessor proofs while retaining provenance; bound call-string context, hops, nodes, edges and derived alternatives. Recursion or a cycle must not increase confidence each time it is traversed. Unbounded offset growth in pointer loops becomes a symbolic stride/range constraint or stops as unresolved, rather than generating infinitely many byte offsets.

A layout change creates a new immutable layout revision, with explicit split/merge/move mappings for fields. Old observations remain attached to old views. Invalidate derived constraints that depended on changed seeds, layouts, call mappings or microcode. If a dependency is not precise, mark the broader affected scope for review. Recompute after IDA/SQLite sync and report an impact delta; do not silently relabel an old inference as freshly observed evidence.

Job summaries should retain accepted facts, hypotheses, decisions, rejected alternatives, the current unresolved edge and next experiment. Detailed previews, acceptances and revision deltas belong in append-only history. A retracted A→E chain resumes at the first invalid dependency with preserved branch history, not by repeating the entire exploration from memory.

### Incremental implementation and acceptance criteria

1. Extract revision-scoped definition/use and object projections within a function; validate load/store/address-taking/offset transforms before cross-function traversal.
2. Add direct-call argument/formal and return/result mappings with explicit convention evidence. Unknown indirect calls remain unresolved.
3. Implement bounded preview with provenance, deduplication, conflict branches and termination diagnostics. Store accepted constraints only after source-revision validation.
4. Add layout revisions and job dependency invalidation; then evaluate object-level matching and discrimination between union views/common prefixes.

Use zlib for the current test phase. Required propagation tests include pointer-offset parameters, multiple callers with conflicting uses, returned subobjects, hidden return arguments, recursive calls, alias ambiguity, storage reuse, stale previews and layout split/merge. Labels from source can judge correctness but must not enter the reverse-engineering evidence. Until those parts exist and pass validation, do not advertise a callable propagation command.
