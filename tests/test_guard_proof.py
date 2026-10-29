"""guard-verify proof: PASS only for a fresh, completed, canonical success on this head.

Each negative changes one fact from a known-good fixture so the failure names
that fact. The candidate's own ci.yml is part of the fixture: it must carry the
trusted base's guard digest, so a forged guard job is rejected by the proof alone.
"""
import base64
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "tools")
import guard_proof as gp  # noqa: E402
import workflow_lint as w  # noqa: E402

REPO = "mao2009/oss-pce-cd-bios-security-test"
HEAD = "a" * 40
OTHER = "b" * 40
PR = 30
RUN = 40812642607
JOB = 123246428000
CHECK = 123246428764
NOW = datetime(2026, 10, 29, 4, 0, tzinfo=timezone.utc)
RECENT = (NOW - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
OLD = (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
REQUIRED = []
BASE_CI = Path(".github/workflows/ci.yml").read_bytes().decode("utf-8").replace("\r\n", "\n")
BASE_DIGEST = w.canonical_digest(w.parse_workflow(BASE_CI)["jobs"]["guard-verify"])
NAMED_CI = BASE_CI.replace(
    "  guard-verify:\n    needs: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo guard\n",
    "  guard-verify:\n    needs: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Trusted guard (main)\n        run: echo guard\n",
)


def check(**over):
    c = {
        "id": CHECK,
        "name": "guard-verify",
        "head_sha": HEAD,
        "status": "completed",
        "conclusion": "success",
        "completed_at": RECENT,
        "app": {"id": gp.GITHUB_ACTIONS_APP_ID},
        "html_url": "https://github.com/%s/actions/runs/%d/job/%d" % (REPO, RUN, JOB),
    }
    c.update(over)
    return c


def run(**over):
    r = {
        "id": RUN,
        "head_sha": HEAD,
        "event": "pull_request",
        "path": ".github/workflows/ci.yml",
        "status": "completed",
        "conclusion": "success",
        "pull_requests": [{"number": PR}],
    }
    r.update(over)
    return r


def job(**over):
    j = {
        "id": JOB,
        "name": "guard-verify",
        "head_sha": HEAD,
        "status": "completed",
        "conclusion": "success",
        "steps": [{"name": "Trusted guard (main)", "conclusion": "success"}],
    }
    j.update(over)
    return j


def write_case(checks=None, runs=None, jobs=None, ci_text=None, ci_present=True, required_runs=None, complete=True):
    d = Path(tempfile.mkdtemp())
    runs_list = runs if runs is not None else [run()]
    (d / "cr.json").write_text(json.dumps({"check_runs": checks if checks is not None else [check()], "total_count": len(checks if checks is not None else [check()]), "complete": complete}), encoding="utf-8")
    (d / "runs.json").write_text(json.dumps({"workflow_runs": runs_list, "total_count": len(runs_list), "complete": complete}), encoding="utf-8")
    for r in runs_list:
        (d / ("jobs-%d.json" % r["id"])).write_text(json.dumps({"jobs": jobs if jobs is not None else [job()], "total_count": len(jobs if jobs is not None else [job()]), "complete": complete}), encoding="utf-8")
    if ci_present:
        text = ci_text if ci_text is not None else BASE_CI
        content = base64.b64encode(text.encode("utf-8")).decode("ascii")
        (d / "ci-contents.json").write_text(json.dumps({"content": content}), encoding="utf-8")
    return d


def verdict(d, head=HEAD, required=REQUIRED):
    return gp.verify_guard(d, REPO, PR, head, required, BASE_DIGEST, NOW)


class Control(unittest.TestCase):
    def test_fresh_canonical_success_passes(self):
        v, proof = verdict(write_case())
        self.assertEqual(v, "PASS")
        self.assertEqual(proof["run_id"], RUN)
        self.assertEqual(proof["job_id"], JOB)


class Negatives(unittest.TestCase):
    def assertFails(self, d, needle, head=HEAD, required=REQUIRED):
        v, proof = verdict(d, head=head, required=required)
        self.assertIsNone(proof)
        self.assertTrue(v.startswith("FAIL"), v)
        self.assertIn(needle, v)

    def test_01_guard_check_missing_is_pending_not_pass(self):
        v, proof = verdict(write_case(checks=[]))
        self.assertIsNone(proof)
        self.assertTrue(v.startswith("PENDING"), v)

    def test_02_guard_failure(self):
        self.assertFails(write_case(checks=[check(conclusion="failure")]), "conclusion is failure")

    def test_03_guard_skipped(self):
        self.assertFails(write_case(checks=[check(conclusion="skipped")]), "conclusion is skipped")

    def test_04_guard_neutral(self):
        self.assertFails(write_case(checks=[check(conclusion="neutral")]), "conclusion is neutral")

    def test_05_guard_still_running_is_pending(self):
        v, proof = verdict(write_case(checks=[check(status="in_progress", conclusion=None)]))
        self.assertTrue(v.startswith("PENDING"), v)
        self.assertIsNone(proof)

    def test_06_guard_conclusion_unknown(self):
        self.assertFails(write_case(checks=[check(conclusion=None)]), "conclusion is None")

    def test_07_guard_expired(self):
        self.assertFails(write_case(checks=[check(completed_at=OLD)]), "expired")

    def test_08_guard_no_completion_time(self):
        self.assertFails(write_case(checks=[check(completed_at=None)]), "completion time is invalid")

    def test_09_same_name_from_other_app_is_ignored(self):
        self.assertFails(write_case(checks=[check(app={"id": 999999})]), "untrusted app")

    def test_10_check_for_other_head(self):
        self.assertFails(write_case(checks=[check(head_sha=OTHER)]), "different head")

    def test_11_run_head_mismatch(self):
        self.assertFails(write_case(runs=[run(head_sha=OTHER)]), "run head does not match")

    def test_12_merge_commit_is_not_the_pr_head(self):
        self.assertFails(write_case(runs=[run(head_sha=OTHER)]), "run head does not match", head=HEAD)

    def test_13_wrong_event(self):
        self.assertFails(write_case(runs=[run(event="push")]), "ran under event push")

    def test_14_wrong_workflow_path(self):
        self.assertFails(write_case(runs=[run(path=".github/workflows/evil.yml")]), "ran from")

    def test_15_run_not_for_this_pr(self):
        self.assertFails(write_case(runs=[run(pull_requests=[{"number": 99}])]), "not associated with this PR")

    def test_16_run_failed(self):
        self.assertFails(write_case(runs=[run(conclusion="failure")]), "run is completed/failure")

    def test_17_job_failed(self):
        self.assertFails(write_case(jobs=[job(conclusion="failure")]), "guard-verify job is completed/failure")

    def test_18_job_skipped(self):
        self.assertFails(write_case(jobs=[job(conclusion="skipped")]), "guard-verify job is completed/skipped")

    def test_19_required_step_not_success(self):
        named = write_case(jobs=[job(steps=[{"name": "Trusted guard (main)", "conclusion": "skipped"}])])
        self.assertFails(named, "required guard step", required=["Trusted guard (main)"])

    def test_20_required_step_absent(self):
        named = write_case(jobs=[job(steps=[])])
        self.assertFails(named, "required guard step", required=["Trusted guard (main)"])

    def test_21_run_reference_names_a_run_not_in_runs(self):
        self.assertFails(write_case(checks=[check(html_url="https://github.com/%s/actions/runs/1/job/%d" % (REPO, JOB))]), "not among the head's pull_request runs")

    def test_22_run_reference_for_other_repository(self):
        self.assertFails(write_case(checks=[check(html_url="https://github.com/other/repo/actions/runs/%d/job/%d" % (RUN, JOB))]), "no run reference")

    def test_23_job_head_mismatch(self):
        self.assertFails(write_case(jobs=[job(head_sha=OTHER)]), "job head does not match")

    def test_24_unreadable_data(self):
        d = write_case()
        (d / "runs.json").write_text("{not json", encoding="utf-8")
        self.assertFails(d, "unreadable")

    def test_25_latest_rerun_failure_beats_older_success(self):
        old_success = check(completed_at=(NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        newer_failure = check(id=CHECK + 1, conclusion="failure", completed_at=RECENT)
        self.assertFails(write_case(checks=[old_success, newer_failure]), "conclusion is failure")

    def test_26_old_success_from_older_head_is_not_reused(self):
        d = write_case(checks=[check(head_sha=OTHER)], runs=[run(head_sha=OTHER)])
        self.assertFails(d, "different head")

    # --- M1: the proof must reject a forged guard-verify on its own ---

    def test_27_forged_guard_job_in_candidate_ci_is_rejected_without_evaluate(self):
        # Every API fact looks good, but the candidate's guard job was replaced.
        forged = BASE_CI.replace("  guard-verify:\n", "  guard-verify:\n    if: false\n")
        self.assertFails(write_case(ci_text=forged), "candidate guard-verify job differs from the trusted base")

    def test_28_candidate_ci_without_guard_job_is_rejected(self):
        no_guard = BASE_CI.split("  guard-verify:")[0].rstrip() + "\n"
        self.assertFails(write_case(ci_text=no_guard), "differs from the trusted base")

    def test_29_missing_candidate_ci_contents_is_rejected(self):
        self.assertFails(write_case(ci_present=False), "candidate ci.yml unreadable")

    def test_30_listing_at_page_limit_fails_closed(self):
        many = [check(id=CHECK + i, conclusion="failure", completed_at=RECENT) for i in range(100)]
        self.assertFails(write_case(checks=many, complete=False), "completeness not established")


    def test_31_two_jobs_named_guard_verify_are_ambiguous(self):
        # A candidate job with `name: guard-verify` must not let the proof pick the wrong job.
        d = write_case(jobs=[job(), job(id=JOB + 1)])
        self.assertFails(d, "expected exactly one guard-verify job")

    def test_32_runs_listing_at_page_limit_fails_closed(self):
        many = [run(id=RUN + i) for i in range(100)]
        self.assertFails(write_case(runs=many, checks=[check()], complete=False), "completeness not established")

    def test_33_duplicate_key_in_candidate_ci_reports_the_reason(self):
        dup = "on: push\n" + BASE_CI
        self.assertFails(write_case(ci_text=dup), "duplicate key")


class Rerun(unittest.TestCase):
    def test_newer_success_after_older_failure_passes(self):
        old_failure = check(id=CHECK + 1, conclusion="failure", completed_at=(NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        newer_success = check(completed_at=RECENT)
        v, proof = verdict(write_case(checks=[old_failure, newer_success]))
        self.assertEqual(v, "PASS")


class RequiredSteps(unittest.TestCase):
    def test_named_base_steps_are_extracted_and_enforced(self):
        base_job = w.parse_workflow(NAMED_CI)["jobs"]["guard-verify"]
        self.assertEqual(gp.required_steps_from_base(base_job), ["Trusted guard (main)"])

    def test_named_step_success_passes_with_named_candidate(self):
        named = write_case(ci_text=NAMED_CI)
        # The digest of the named base job differs from BASE_DIGEST, so compute the expected digest.
        digest = w.canonical_digest(w.parse_workflow(NAMED_CI)["jobs"]["guard-verify"])
        v, proof = gp.verify_guard(named, REPO, PR, HEAD, ["Trusted guard (main)"], digest, NOW)
        self.assertEqual(v, "PASS")


class CliMapping(unittest.TestCase):
    def test_pending_exit_code_is_distinct(self):
        d = write_case(checks=[])
        r = subprocess.run(
            [sys.executable, "tools/guard_proof.py", str(d), REPO, str(PR), HEAD, "."],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 3, r.stdout)

    def test_forged_candidate_exits_nonzero(self):
        forged = BASE_CI.replace("  guard-verify:\n", "  guard-verify:\n    if: false\n")
        d = write_case(ci_text=forged)
        r = subprocess.run(
            [sys.executable, "tools/guard_proof.py", str(d), REPO, str(PR), HEAD, "."],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1, r.stdout)


if __name__ == "__main__":
    unittest.main()
