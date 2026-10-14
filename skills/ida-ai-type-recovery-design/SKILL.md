---
name: ida-ai-type-recovery-design
description: Design AI-assisted type-recovery features that expose usage evidence, propagate constraints, and explain compatible type candidates without claiming automatic source-type recovery.
---

This skill describes the planned type-recovery direction. It is a design reference, not an implemented CLI or MCP feature. Current MCP type operations register/apply declarations and refresh IDA/SQLite views; they do not yet extract microcode usage features, propagate type constraints, or rank candidates.

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
