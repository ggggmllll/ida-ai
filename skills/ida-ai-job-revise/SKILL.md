---
name: ida-ai-job-revise
description: Record research claims, evidence, questions, dependencies, validation, and detailed analysis in a new job VCS revision.
---

Every call appends an immutable revision. Provide `--message` and use `--details` for reasoning and experimental notes so a later resume can see what changed and why. A successful IDA sync/export/write/mutation checks evidence drift automatically; job revisions also apply any pending review transitions atomically before accepting the edit.

For long notes or multiple edits, put the changes in a UTF-8 JSON object under a temporary ignored path such as `.ida-ai-cache/job-patch.json`, then run `python -m ida_ai job-revise --db ANALYSIS.sqlite --job JOB_ID --message "Why this changed" --patch-file .ida-ai-cache/job-patch.json`. The file can contain `details`, `expected_revision_id`, `handoff`, `add_evidence`, `add_claims`, `update_claims`, `withdraw_claims`, `add_questions`, `resolve_questions`, `add_dependencies`, `remove_dependencies`, `operation_ids`, `validations`, `status`, `title`, and `objective`. The list fields for claims/evidence contain JSON objects. `handoff` is an object with non-empty `progress`, `next_action`, and `stop_condition`. Do not mix `--patch-file` with other change flags.

Claims are JSON objects passed through repeatable `--add-claim` or `--update-claim` flags. Kinds are `fact`, `hypothesis`, `decision`, and `reject`. Facts require `basis` set to `observed` or `derived`; reject claims require `rationale`. Claims may include `summary`, `rationale`, `evidence_ids`, `relies_on` (objects with `job_id` and `claim_id`), and `supersedes` plus a required `supersedes_reason`. Use `rationale` on reject claims to preserve why an interpretation was ruled out. Example:

```powershell
python -m ida_ai job-revise --db ANALYSIS.sqlite --job 1 --message "Confirm read width" --details "Compared both call sites." --add-claim '{"kind":"fact","basis":"observed","text":"The field is read as eight bytes","summary":"8-byte read","evidence_ids":["E0001"]}'
```

Evidence is added as JSON with required `source_ref` and `description`; optional `kind` values are `observation`, `derived`, `experiment`, `artifact`, `external`, or `analyst_note`. Set `origin` to `raw`, `ida_analysis`, `ida_type_dependent`, `external`, or `analyst`. Keep original bytes/assembly and IDA-type-dependent pseudocode evidence distinct. Evidence records pin the current analysis snapshot. `job-show`/`job-resume` label raw, external, or analyst evidence without a source fingerprint as untracked, not verified unchanged.

Use `--update-claim` to revise a current claim, `--withdraw-claim '{"id":"C0001","reason":"..."}'` to withdraw it without erasing history, and `supersedes` with `supersedes_reason` when replacing an active or review-required claim. Changing or withdrawing a claim automatically marks jobs that cite it for review, including transitive claim dependents. Reactivating a reviewed claim requires `--details` explaining the re-evaluation and current evidence; stale evidence cannot be reused for a changed/revalidated claim. Restore creates a new revision and validates any reactivated claims against current evidence. IDs are never reused after removal or restore, preserving old references.

Use `--add-question TEXT` and `--resolve-question '{"id":"Q0001","resolution":"..."}'` for open questions. Use `--depends-on JOB_ID` for execution order; these links are cycle-checked and can trigger review when an upstream job changes. `--status` accepts `planned`, `active`, `blocked`, `done`, `stale`, or `needs_review`.

Attach an existing IDA operation with `--ida-operation REQUEST_ID`, record a validation result with `--validation TEXT`, or restore an older snapshot with `--restore-revision REVISION_ID`. Restore appends a new VCS revision. Use `--expected-revision REVISION_ID` from `job-resume` to reject edits based on an outdated job head. Save compact progress and a concrete next experiment using `--handoff '{"progress":"...","next_action":"...","stop_condition":"..."}'`; this handoff is visible in `job-resume`. Check returned `added_claim_ids` and `added_evidence_ids` before linking them in later revisions.

Use `vtrace:<run_id>` for virtual-call memory trace evidence. Its fingerprint validates current durable inputs and the run status; a stale trace requires reanalysis and explicit claim review. It binds an observed candidate analysis, never a confirmed runtime target.
