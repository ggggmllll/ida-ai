from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from ida_ai.cli import _parser, _run
from ida_ai.db import connect, reset_analysis, set_metadata
from ida_ai.jobs import check_jobs, create_job, history, list_jobs, resume_job, revise_job, show_job
from ida_ai.job_queries import diff_job, find_jobs, impact


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = Path(self.temporary.name) / "analysis.sqlite"
        self.connection = closing(connect(self.db_path))
        self.db = self.connection.__enter__()
        set_metadata(self.db, {
            "root_filename": "zlib-test.so", "input_path": "zlib-test.so",
            "imagebase": 0x100000, "bitness": 64,
            "generated_at": "2026-01-01T00:00:00+00:00",
        })
        self.db.execute("INSERT INTO functions(start_ea,end_ea,name,size) VALUES(4096,4112,'inflate',16)")
        self.db.commit()
        self.addCleanup(self.connection.__exit__, None, None, None)

    def add_evidence(self, job_id, source_ref="sql:functions:inflate"):
        return revise_job(
            self.db, job_id, message="Record observation", details="Checked the zlib analysis snapshot.",
            add_evidence=[json.dumps({"kind": "observation", "origin": "ida_analysis",
                                      "source_ref": source_ref, "description": "inflate starts at 0x1000"})],
        )

    def test_job_tree_claims_evidence_and_history_are_versioned(self):
        root = create_job(self.db, title="zlib data flow", objective="Trace input through inflate.")
        child = create_job(self.db, title="inflate stream state", objective="Identify stream state fields.", parent_job_id=root["job_id"])
        evidence_revision = self.add_evidence(root["job_id"])
        root_state = show_job(self.db, root["job_id"])
        self.assertEqual(root_state["evidence"][0]["id"], "E0001")
        self.assertEqual(root_state["evidence"][0]["analysis_snapshot"]["identity"]["root_filename"], "zlib-test.so")

        revision = revise_job(
            self.db, root["job_id"], message="Record the function boundary", status="active",
            add_claims=[json.dumps({"kind": "fact", "basis": "observed", "text": "inflate is a function at 0x1000",
                                   "summary": "inflate starts at 0x1000", "evidence_ids": ["E0001"]})],
            add_questions=["Which field stores the current input position?"],
        )
        self.assertEqual(revision["revision_no"], evidence_revision["revision_no"] + 1)
        self.assertEqual(show_job(self.db, root["job_id"])["claims"][0]["id"], "C0001")
        self.assertEqual(list_jobs(self.db, tree=True)["tree"][0]["children"][0]["job_id"], child["job_id"])
        self.assertEqual(resume_job(self.db, root["job_id"])["open_questions"][0]["id"], "Q0001")

        old_revision = history(self.db, root["job_id"], limit=1, include_state=True)["revisions"][0]
        self.assertEqual(old_revision["revision_no"], revision["revision_no"])
        self.assertEqual(old_revision["state"]["claims"][0]["text"], "inflate is a function at 0x1000")

    def test_upstream_claim_changes_propagate_to_descendants(self):
        root = create_job(self.db, title="CSV parser", objective="Understand stored CSV records.")
        root_claim_revision = revise_job(
            self.db, root["job_id"], message="Add initial observation",
            add_claims=[json.dumps({"kind": "fact", "basis": "observed", "id": "STREAM", "text": "parser reads four bytes", "summary": "four-byte reads"})],
        )
        left = create_job(self.db, title="Reader behavior", objective="Trace parser reads.", parent_job_id=root["job_id"])
        left_claim_revision = revise_job(
            self.db, left["job_id"], message="Link reader conclusion",
            add_claims=[json.dumps({"kind": "hypothesis", "id": "READ", "text": "The field is a 32-bit value", "summary": "32-bit field",
                                   "relies_on": [{"job_id": root["job_id"], "claim_id": "STREAM"}]})],
        )
        leaf = create_job(self.db, title="Record effect", objective="Determine how one value affects control flow.", parent_job_id=left["job_id"])
        revise_job(
            self.db, leaf["job_id"], message="Link record effect",
            add_claims=[json.dumps({"kind": "hypothesis", "id": "EFFECT", "text": "It controls a loop bound", "summary": "loop bound",
                                   "relies_on": [{"job_id": left["job_id"], "claim_id": "READ"}]})],
        )

        changed = revise_job(
            self.db, root["job_id"], message="Correct the read width", details="A second call site reads eight bytes.",
            update_claims=[json.dumps({"id": "STREAM", "text": "parser reads at least eight bytes", "summary": "at least eight-byte reads"})],
        )
        self.assertEqual(changed["changed_claims"], ["STREAM"])
        self.assertEqual(set(changed["jobs_marked_needs_review"]), {left["job_id"], leaf["job_id"]})
        self.assertEqual(show_job(self.db, left["job_id"])["claims"][0]["status"], "review_required")
        self.assertEqual(show_job(self.db, leaf["job_id"])["status"], "needs_review")
        self.assertEqual(show_job(self.db, root["job_id"])["claims"][0]["text"], "parser reads at least eight bytes")
        self.assertEqual(history(self.db, root["job_id"], limit=0, include_state=True)["revisions"][0]["state"]["claims"], [])
        self.assertEqual(root_claim_revision["revision_no"], 2)
        self.assertEqual(left_claim_revision["revision_no"], 2)

        resume = resume_job(self.db, left["job_id"])
        self.assertEqual(resume["claims_needing_review"][0]["id"], "READ")
        with self.assertRaisesRegex(ValueError, "requires --details"):
            revise_job(self.db, left["job_id"], message="Invalid reactivation", update_claims=[
                json.dumps({"id": "READ", "status": "active"}),
            ])
        revise_job(self.db, left["job_id"], message="Revalidate against corrected width",
                   details="The field remains plausible after checking the wider access.",
                   update_claims=[json.dumps({"id": "READ", "status": "active", "text": "The field is at least 32 bits"})],
                   status="active")
        self.assertEqual(show_job(self.db, left["job_id"])["claims"][0]["status"], "active")
        revise_job(self.db, root["job_id"], message="Withdraw unsupported observation",
                   withdraw_claims=[json.dumps({"id": "STREAM", "reason": "The read was from a different object"})])
        with self.assertRaisesRegex(ValueError, "unavailable claim"):
            revise_job(self.db, left["job_id"], message="Cannot revalidate with withdrawn upstream",
                       details="No replacement evidence was found.",
                       update_claims=[json.dumps({"id": "READ", "status": "active"})])

    def test_dependency_cycles_and_self_references_are_rejected(self):
        first = create_job(self.db, title="First", objective="First objective.")
        second = create_job(self.db, title="Second", objective="Second objective.")
        revise_job(self.db, first["job_id"], message="Depends on second", add_dependencies=[second["job_id"]])
        with self.assertRaisesRegex(ValueError, "cannot contain a cycle"):
            revise_job(self.db, second["job_id"], message="Cycle", add_dependencies=[first["job_id"]])
        with self.assertRaisesRegex(ValueError, "cannot contain a cycle"):
            revise_job(self.db, first["job_id"], message="Self-referential claim", add_claims=[json.dumps({
                "id": "LOOP", "kind": "hypothesis", "text": "Circular claim", "summary": "circular",
                "relies_on": [{"job_id": first["job_id"], "claim_id": "LOOP"}],
            })])

    def test_changed_upstream_job_marks_active_dependents_for_review(self):
        shared = create_job(self.db, title="Shared decryption", objective="Understand the shared decryptor.")
        csv = create_job(self.db, title="CSV reader", objective="Understand encrypted CSV storage.")
        yaml = create_job(self.db, title="YAML reader", objective="Understand encrypted YAML storage.")
        for job in (csv, yaml):
            revise_job(self.db, job["job_id"], message="Depend on shared decryptor",
                       add_dependencies=[shared["job_id"]], status="active")
        result = revise_job(self.db, shared["job_id"], message="Correct decryptor objective",
                            objective="Identify the shared key derivation and decryption.")
        self.assertEqual(set(result["jobs_marked_needs_review"]), {csv["job_id"], yaml["job_id"]})
        self.assertEqual(show_job(self.db, csv["job_id"])["status"], "needs_review")

    def test_snapshot_changes_and_analysis_reset_do_not_delete_jobs(self):
        job = create_job(self.db, title="Snapshot check", objective="Notice refreshed exports.")
        revise_job(self.db, job["job_id"], message="Add question", add_questions=["What changed?"])
        before = resume_job(self.db, job["job_id"])
        self.assertFalse(before["analysis_snapshot_changed"])
        set_metadata(self.db, {"synchronized_at": "2026-01-02T00:00:00+00:00"})
        self.assertTrue(resume_job(self.db, job["job_id"])["analysis_snapshot_changed"])
        reset_analysis(self.db)
        self.db.commit()
        self.assertEqual(show_job(self.db, job["job_id"])["title"], "Snapshot check")

    def test_type_dependent_evidence_is_tied_to_its_exported_function(self):
        self.db.execute("INSERT INTO pseudocode(function_ea,text,status,generated_at) VALUES(4096,'return value;', 'ok', 'v1')")
        self.db.commit()
        job = create_job(self.db, title="Type dependent", objective="Record a decompiler-based interpretation.")
        revise_job(self.db, job["job_id"], message="Add typed pseudocode evidence",
                   add_evidence=[json.dumps({"kind": "observation", "origin": "ida_type_dependent",
                                             "source_ref": "pseudocode:0x1000", "description": "The decompiler shows a 32-bit field"})],
                   add_claims=[json.dumps({"kind": "hypothesis", "text": "Field is a signed int",
                                           "evidence_ids": ["E0001"]})])
        self.assertFalse(resume_job(self.db, job["job_id"])["claims_needing_type_review"])
        self.db.execute("UPDATE pseudocode SET text='return (value >> 32);' WHERE function_ea=4096")
        self.db.commit()
        resumed = resume_job(self.db, job["job_id"])
        self.assertTrue(resumed["claims_needing_type_review"])
        self.assertTrue(resumed["known_evidence_scope"][0]["source_changed"])

    def test_raw_evidence_remains_valid_when_only_exported_views_change(self):
        job = create_job(self.db, title="Raw evidence", objective="Keep byte observations independent of decompiler refreshes.")
        revise_job(self.db, job["job_id"], message="Record raw bytes",
                   add_evidence=[json.dumps({"kind": "observation", "origin": "raw",
                                             "source_ref": "memory:0x1000", "description": "Raw byte was observed"})])
        set_metadata(self.db, {"synchronized_at": "2026-01-02T00:00:00+00:00"})
        resumed = resume_job(self.db, job["job_id"])
        self.assertIsNone(resumed["known_evidence_scope"][0]["source_changed"])
        self.assertEqual(resumed["known_evidence_scope"][0]["drift_check"], "untracked")

    def test_reject_claim_requires_reason(self):
        job = create_job(self.db, title="Reject", objective="Record ruled-out interpretations.")
        with self.assertRaisesRegex(ValueError, "reject claims require rationale"):
            revise_job(self.db, job["job_id"], message="Missing reason", add_claims=[json.dumps({
                "kind": "reject", "text": "It is a double", "summary": "double candidate",
            })])

    def test_restore_appends_revision_and_preserves_history(self):
        job = create_job(self.db, title="Restore", objective="Keep the history linear.")
        first_revision_id = job["revision_id"]
        revise_job(self.db, job["job_id"], message="Rename", title="Renamed")
        restored = revise_job(self.db, job["job_id"], message="Return to initial title", restore_revision_id=first_revision_id)
        self.assertEqual(show_job(self.db, job["job_id"])["title"], "Restore")
        self.assertEqual(restored["revision_no"], 3)
        self.assertEqual(history(self.db, job["job_id"], limit=0)["count"], 3)
        with self.assertRaisesRegex(Exception, "immutable"):
            self.db.execute("UPDATE job_revisions SET message='rewritten' WHERE revision_id=?", (first_revision_id,))

    def test_cli_patch_file_can_record_detailed_revision_without_shell_json(self):
        job = create_job(self.db, title="CLI patch", objective="Record analysis notes.")
        patch = Path(self.temporary.name) / "changes.json"
        patch.write_text(json.dumps({
            "details": "Inspected the disassembly and xrefs.",
            "expected_revision_id": job["revision_id"],
            "handoff": {"progress": "Inspected inflate", "next_action": "Trace callers",
                        "stop_condition": "All direct callers classified"},
            "add_evidence": [{"kind": "observation", "origin": "ida_analysis",
                              "source_ref": "functions:0x1000", "description": "Function starts at 0x1000"}],
            "add_claims": [{"kind": "fact", "basis": "observed", "text": "A function starts at 0x1000",
                            "evidence_ids": ["E0001"]}],
            "add_questions": ["Which call sites use this function?"],
        }), encoding="utf-8")
        args = _parser().parse_args(["job-revise", "--db", str(self.db_path), "--job", str(job["job_id"]),
                                     "--message", "Record first pass", "--patch-file", str(patch)])
        result = _run(args)
        self.assertEqual(result["added_claim_ids"], ["C0001"])
        self.assertEqual(result["added_evidence_ids"], ["E0001"])
        self.assertNotIn("details", resume_job(self.db, job["job_id"])["latest_revision"])
        self.assertEqual(history(self.db, job["job_id"], revision_id=result["revision_id"])["revisions"][0]["details"],
                         "Inspected the disassembly and xrefs.")
        self.assertEqual(resume_job(self.db, job["job_id"])["handoff"]["next_action"], "Trace callers")

    def test_restore_never_reuses_claim_evidence_or_question_ids(self):
        job = create_job(self.db, title="Stable identifiers", objective="Keep old references unambiguous.")
        first = revise_job(
            self.db, job["job_id"], message="Initial records",
            add_evidence=[json.dumps({"origin": "raw", "source_ref": "memory:0x1000", "description": "byte"})],
            add_claims=[json.dumps({"kind": "hypothesis", "text": "Initial interpretation", "summary": "initial"})],
            add_questions=["Initial question"],
        )
        restored = revise_job(self.db, job["job_id"], message="Restore empty scope",
                              restore_revision_id=job["revision_id"])
        self.assertEqual(restored["revision_no"], 3)
        added = revise_job(
            self.db, job["job_id"], message="Add replacement records",
            add_evidence=[json.dumps({"origin": "raw", "source_ref": "memory:0x1001", "description": "next byte"}),
                          json.dumps({"origin": "raw", "source_ref": "memory:0x1002", "description": "following byte"})],
            add_claims=[json.dumps({"kind": "hypothesis", "text": "Replacement one", "summary": "one"}),
                        json.dumps({"kind": "hypothesis", "text": "Replacement two", "summary": "two"})],
            add_questions=["Replacement question", "Another replacement question"],
        )
        self.assertEqual(added["added_evidence_ids"], ["E0002", "E0003"])
        self.assertEqual(added["added_claim_ids"], ["C0002", "C0003"])
        self.assertEqual(added["added_question_ids"], ["Q0002", "Q0003"])
        self.assertEqual(first["added_claim_ids"], ["C0001"])

    def test_evidence_drift_is_previewed_then_applied_transitively_once(self):
        self.db.execute("INSERT INTO pseudocode(function_ea,text,status,generated_at) VALUES(4096,'return 1;', 'ok', 'v1')")
        self.db.commit()
        root = create_job(self.db, title="Root evidence", objective="Inspect typed decompilation.")
        revise_job(
            self.db, root["job_id"], message="Record typed output",
            add_evidence=[json.dumps({"origin": "ida_type_dependent", "source_ref": "pseudocode:0x1000",
                                      "description": "Decompiler output after applying current types"})],
            add_claims=[json.dumps({"id": "ROOT", "kind": "hypothesis", "text": "A field is signed",
                                    "summary": "signed field", "evidence_ids": ["E0001"]})],
            status="active",
        )
        child = create_job(self.db, title="Child", objective="Follow the field.", parent_job_id=root["job_id"])
        revise_job(self.db, child["job_id"], message="Derive field use", status="active",
                   add_claims=[json.dumps({"id": "CHILD", "kind": "hypothesis", "text": "It controls a branch",
                                           "summary": "branch control", "relies_on": [{"job_id": root["job_id"], "claim_id": "ROOT"}]})])
        leaf = create_job(self.db, title="Leaf", objective="Follow branch effect.", parent_job_id=child["job_id"])
        revise_job(self.db, leaf["job_id"], message="Derive downstream effect", status="active",
                   add_claims=[json.dumps({"id": "LEAF", "kind": "hypothesis", "text": "It bounds a loop",
                                           "summary": "loop bound", "relies_on": [{"job_id": child["job_id"], "claim_id": "CHILD"}]})])

        self.db.execute("UPDATE type_assignments SET declaration='long long' WHERE address=4096")
        self.db.execute("INSERT INTO type_assignments(address,declaration,updated_at) VALUES(4096,'long long','v2')")
        self.db.commit()
        preview = check_jobs(self.db)
        self.assertEqual({(item["job_id"], item["claim_id"]) for item in preview["claims_requiring_review"]},
                         {(root["job_id"], "ROOT"), (child["job_id"], "CHILD"), (leaf["job_id"], "LEAF")})
        self.assertEqual({item["job_id"] for item in preview["jobs_requiring_review"]},
                         {root["job_id"], child["job_id"], leaf["job_id"]})
        self.assertTrue(resume_job(self.db, root["job_id"])["claims_needing_review"])
        self.assertEqual(resume_job(self.db, root["job_id"])["effective_status"], "needs_review")

        applied = check_jobs(self.db, apply=True)
        self.assertEqual(set(applied["jobs_revised"]), {root["job_id"], child["job_id"], leaf["job_id"]})
        counts = {job_id: history(self.db, job_id, limit=0)["count"]
                  for job_id in (root["job_id"], child["job_id"], leaf["job_id"])}
        again = check_jobs(self.db, apply=True)
        self.assertEqual(again["jobs_revised"], [])
        self.assertEqual({job_id: history(self.db, job_id, limit=0)["count"]
                          for job_id in counts}, counts)
        self.assertFalse(resume_job(self.db, root["job_id"])["current_claims"]["hypothesis"])
        self.assertEqual(show_job(self.db, leaf["job_id"])["claims"][0]["status"], "review_required")

    def test_revalidation_requires_fresh_evidence_and_stale_cannot_be_marked_done(self):
        self.db.execute("INSERT INTO pseudocode(function_ea,text,status,generated_at) VALUES(4096,'return x;', 'ok', 'v1')")
        self.db.commit()
        job = create_job(self.db, title="Revalidation", objective="Use current decompiler evidence.")
        revise_job(self.db, job["job_id"], message="Initial typed evidence",
                   add_evidence=[json.dumps({"origin": "ida_type_dependent", "source_ref": "pseudocode:0x1000",
                                             "description": "Initial typed pseudocode"})],
                   add_claims=[json.dumps({"kind": "hypothesis", "id": "FIELD", "text": "Field is 32-bit",
                                           "summary": "32-bit field", "evidence_ids": ["E0001"]})],
                   status="active")
        self.db.execute("UPDATE pseudocode SET text='return x + 1;' WHERE function_ea=4096")
        self.db.commit()
        with self.assertRaisesRegex(ValueError, "review-required claims"):
            revise_job(self.db, job["job_id"], message="Premature completion", status="done")
        # Failed edits roll back their automatic review revision, but resume and
        # show still make the effective review state explicit.
        self.assertEqual(show_job(self.db, job["job_id"])["effective_status"], "needs_review")
        self.assertEqual(history(self.db, job["job_id"], limit=0)["count"], 2)
        revised = revise_job(
            self.db, job["job_id"], message="Re-evaluate with fresh pseudocode",
            details="Re-read the refreshed function and confirmed the 32-bit access remains.",
            status="active",
            add_evidence=[json.dumps({"origin": "ida_type_dependent", "source_ref": "pseudocode:0x1000",
                                      "description": "Refreshed pseudocode after review"})],
            update_claims=[json.dumps({"id": "FIELD", "status": "active", "evidence_ids": ["E0002"]})],
        )
        self.assertEqual(revised["status"], "active")
        self.assertEqual(show_job(self.db, job["job_id"])["claims"][0]["status"], "active")
        self.assertEqual(show_job(self.db, job["job_id"])["claims"][0]["evidence_ids"], ["E0002"])

    def test_revision_guard_and_handoff_validation(self):
        job = create_job(self.db, title="Optimistic revision", objective="Avoid editing stale context.")
        with self.assertRaisesRegex(ValueError, "job head changed"):
            revise_job(self.db, job["job_id"], message="Stale writer", expected_revision_id=999,
                       title="Should not be written")
        self.assertEqual(history(self.db, job["job_id"], limit=0)["count"], 1)
        with self.assertRaisesRegex(ValueError, "handoff requires"):
            revise_job(self.db, job["job_id"], message="Incomplete handoff", handoff=json.dumps({"progress": "done"}))
        result = revise_job(self.db, job["job_id"], message="Save handoff",
                            expected_revision_id=job["revision_id"],
                            handoff=json.dumps({"progress": "read function", "next_action": "inspect callers",
                                                "stop_condition": "all callers classified"}))
        self.assertEqual(result["revision_no"], 2)

    def test_new_cli_queries_and_check(self):
        job = create_job(self.db, title="CLI retrieval", objective="Locate research history.")
        revise_job(self.db, job["job_id"], message="Record a searchable note", details="unique marker")
        commands = [
            ["job-diff", "--job", str(job["job_id"]), "--from-revision", str(job["revision_id"])],
            ["job-search", "--query", "unique marker", "--kind", "note"],
            ["job-impact", "--job", str(job["job_id"])],
            ["job-check"], ["job-check", "--apply"],
        ]
        results = [_run(_parser().parse_args(command + ["--db", str(self.db_path)])) for command in commands]
        self.assertEqual(results[0]["from_revision"], job["revision_id"])
        self.assertEqual(results[1]["count"], 1)
        self.assertEqual(results[2]["job_ids"], [])
        self.assertFalse(results[3]["applied"])
        self.assertTrue(results[4]["applied"])

    def test_job_diff_impact_and_historical_search(self):
        root = create_job(self.db, title="Root", objective="Understand a buffer.")
        initial = revise_job(self.db, root["job_id"], message="Record buffer hypothesis",
                             add_claims=[json.dumps({"id": "BUFFER", "kind": "hypothesis",
                                                     "text": "The input is a byte buffer", "summary": "byte buffer"})])
        child = create_job(self.db, title="Consumer", objective="Trace buffer consumer.", parent_job_id=root["job_id"])
        revise_job(self.db, child["job_id"], message="Link consumer", add_claims=[json.dumps({
            "id": "USE", "kind": "hypothesis", "text": "Consumer advances a pointer", "summary": "pointer advance",
            "relies_on": [{"job_id": root["job_id"], "claim_id": "BUFFER"}],
        })])
        current = revise_job(self.db, root["job_id"], message="Refine buffer hypothesis",
                             update_claims=[json.dumps({"id": "BUFFER", "text": "The input is a length-delimited byte buffer",
                                                        "summary": "length-delimited byte buffer"})])
        difference = diff_job(self.db, root["job_id"], from_revision=initial["revision_id"], to_revision=current["revision_id"])
        self.assertEqual(difference["changed_claim_ids"], ["BUFFER"])
        self.assertEqual(difference["potential_impact"]["claims"][0]["claim_id"], "USE")
        effect = impact(self.db, root["job_id"], ["BUFFER"])
        self.assertEqual(effect["job_ids"], [child["job_id"]])
        with self.assertRaisesRegex(ValueError, "not found"):
            impact(self.db, root["job_id"], ["TYPO"])
        self.assertTrue(find_jobs(self.db, query="byte buffer", job_id=root["job_id"])["matches"])
        revise_job(self.db, root["job_id"], message="Change terminology",
                   update_claims=[json.dumps({"id": "BUFFER", "text": "The input is a bounded octet sequence",
                                              "summary": "bounded octets"})])
        self.assertFalse(find_jobs(self.db, query="byte buffer", job_id=root["job_id"])["matches"])
        self.assertTrue(find_jobs(self.db, query="byte buffer", job_id=root["job_id"], include_history=True)["matches"])

        downstream = create_job(self.db, title="Execution dependent", objective="Wait for root completion.")
        revise_job(self.db, downstream["job_id"], message="Add job dependency", add_dependencies=[root["job_id"]])
        self.assertEqual(impact(self.db, root["job_id"], [])["job_ids"], [downstream["job_id"]])


if __name__ == "__main__":
    unittest.main()
