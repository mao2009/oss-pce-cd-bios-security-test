"""M5 freshness: a success is published only for one PR head, one main, one run, one policy.

Each negative changes exactly one fact from a known-good state, so a failure points at
that fact. The API is a fake; the App-backed client is not created here.
"""
import copy
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "tools")
import m5_freshness as m  # noqa: E402

REPO = "mao2009/oss-pce-cd-bios-security-test"
HEAD = "a" * 40
BASE = "b" * 40
OTHER = "c" * 40
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)
RUN = 9001


class FakeApi:
    def __init__(self):
        self.pr = {
            "number": 7,
            "state": "open",
            "base": {"ref": "main", "repo": {"full_name": REPO}},
            "head": {"sha": HEAD},
        }
        self.main = BASE
        self.error = None
        self.checks = []

    def get_pr(self, repo, number):
        if self.error is not None:
            raise self.error
        return copy.deepcopy(self.pr)

    def get_ref(self, repo, ref):
        if self.error is not None:
            raise self.error
        return self.main

    def post_check(self, repo, head, conclusion):
        self.checks.append((repo, head, conclusion))


def ctx():
    return {"repo": REPO, "number": 7, "head": HEAD, "base": BASE, "policy": m.POLICY_VERSION}


def record(**over):
    fields = {
        "verdict": "PASS",
        "run_id": RUN,
        "repo": REPO,
        "number": 7,
        "head": HEAD,
        "base": BASE,
        "policy": m.POLICY_VERSION,
        "evaluated_at": (NOW - timedelta(minutes=5)).isoformat(),
    }
    fields.update(over)
    return fields


def post(api, rec=None, run=RUN, now=NOW, conclusion="success", context=None):
    return m.post_verdict(api, context or ctx(), rec if rec is not None else record(), run, now, conclusion)


class PositiveTests(unittest.TestCase):
    def test_fresh_evaluation_posts_success_once(self):
        api = FakeApi()
        self.assertIsNone(m.begin_evaluation(api, ctx()))
        self.assertEqual(post(api), (True, "posted success"))
        self.assertEqual(api.checks, [(REPO, HEAD, "success")])

    def test_fresh_failure_verdict_is_posted_as_failure(self):
        api = FakeApi()
        rec = record(verdict="FAIL")
        self.assertEqual(post(api, rec=rec, conclusion="failure"), (True, "posted failure"))
        self.assertEqual(api.checks, [(REPO, HEAD, "failure")])


class BeginNegativeTests(unittest.TestCase):
    def test_head_moved_before_evaluation(self):
        api = FakeApi()
        api.pr["head"]["sha"] = OTHER
        self.assertIn("head moved", (m.begin_evaluation(api, ctx()) or ""))

    def test_main_moved_before_evaluation(self):
        api = FakeApi()
        api.main = OTHER
        self.assertIn("main moved", (m.begin_evaluation(api, ctx()) or ""))

    def test_closed_pr_denied(self):
        api = FakeApi()
        api.pr["state"] = "closed"
        self.assertIn("not open", (m.begin_evaluation(api, ctx()) or ""))

    def test_base_branch_not_main_denied(self):
        api = FakeApi()
        api.pr["base"]["ref"] = "release"
        self.assertIn("base ref", (m.begin_evaluation(api, ctx()) or ""))

    def test_base_repository_mismatch_denied(self):
        api = FakeApi()
        api.pr["base"]["repo"]["full_name"] = "someone/else"
        self.assertIn("base repository", (m.begin_evaluation(api, ctx()) or ""))

    def test_pr_number_mismatch_denied(self):
        api = FakeApi()
        api.pr["number"] = 8
        self.assertIn("PR number", (m.begin_evaluation(api, ctx()) or ""))

    def test_api_timeout_fails_closed(self):
        api = FakeApi()
        api.error = TimeoutError()
        self.assertIn("API error", (m.begin_evaluation(api, ctx()) or ""))

    def test_malformed_pr_fails_closed(self):
        api = FakeApi()
        del api.pr["head"]
        self.assertIn("missing", (m.begin_evaluation(api, ctx()) or ""))

    def test_malformed_main_fails_closed(self):
        api = FakeApi()
        api.main = "not-a-sha"
        self.assertIn("malformed", (m.begin_evaluation(api, ctx()) or ""))

    def test_untrusted_policy_version_denied(self):
        api = FakeApi()
        self.assertIn("policy", (m.begin_evaluation(api, ctx() | {"policy": "m5-0"}) or ""))

    def test_malformed_head_sha_denied(self):
        api = FakeApi()
        self.assertIn("head SHA", (m.begin_evaluation(api, ctx() | {"head": "xyz"}) or ""))


class PostNegativeTests(unittest.TestCase):
    def assert_denied(self, api, **kwargs):
        posted, reason = post(api, **kwargs)
        self.assertFalse(posted, reason)
        self.assertEqual(api.checks, [])
        return reason

    def test_main_moved_after_evaluation_posts_nothing(self):
        api = FakeApi()
        self.assertIsNone(m.begin_evaluation(api, ctx()))
        api.main = OTHER
        self.assertIn("main moved", self.assert_denied(api))

    def test_head_moved_after_evaluation_posts_nothing(self):
        api = FakeApi()
        self.assertIsNone(m.begin_evaluation(api, ctx()))
        api.pr["head"]["sha"] = OTHER
        self.assertIn("head moved", self.assert_denied(api))

    def test_older_workflow_run_denied(self):
        self.assertIn("another workflow run", self.assert_denied(FakeApi(), run=RUN + 1))

    def test_policy_mismatch_in_record_denied(self):
        self.assertIn("policy", self.assert_denied(FakeApi(), rec=record(policy="m5-0")))

    def test_stale_evaluation_denied(self):
        rec = record(evaluated_at=(NOW - timedelta(hours=2)).isoformat())
        self.assertIn("stale", self.assert_denied(FakeApi(), rec=rec))

    def test_future_evaluation_denied(self):
        rec = record(evaluated_at=(NOW + timedelta(minutes=10)).isoformat())
        self.assertIn("future", self.assert_denied(FakeApi(), rec=rec))

    def test_naive_evaluation_time_denied(self):
        rec = record(evaluated_at="2026-10-29T11:55:00")
        self.assertIn("invalid", self.assert_denied(FakeApi(), rec=rec))

    def test_evaluation_for_other_head_denied(self):
        self.assertIn("another head", self.assert_denied(FakeApi(), rec=record(head=OTHER)))

    def test_evaluation_for_other_base_denied(self):
        self.assertIn("another base", self.assert_denied(FakeApi(), rec=record(base=OTHER)))

    def test_evaluation_for_other_pr_denied(self):
        self.assertIn("another PR", self.assert_denied(FakeApi(), rec=record(number=8)))

    def test_evaluation_for_other_repo_denied(self):
        self.assertIn("another PR", self.assert_denied(FakeApi(), rec=record(repo="x/y")))

    def test_success_without_pass_verdict_denied(self):
        reason = self.assert_denied(FakeApi(), rec=record(verdict="FAIL"), conclusion="success")
        self.assertIn("PASS", reason)

    def test_api_timeout_at_post_posts_nothing(self):
        api = FakeApi()
        self.assertIsNone(m.begin_evaluation(api, ctx()))
        api.error = TimeoutError()
        self.assertIn("API error", self.assert_denied(api))

    def test_unknown_conclusion_denied(self):
        self.assertIn("malformed", self.assert_denied(FakeApi(), conclusion="neutral"))

    def test_non_mapping_record_denied(self):
        self.assertIn("not a mapping", self.assert_denied(FakeApi(), rec="PASS"))


if __name__ == "__main__":
    unittest.main()
