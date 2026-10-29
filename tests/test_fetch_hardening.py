"""Hardening: bounded paging, bounded retries, fail closed, and strict timestamps.

Fetch tests use a fake gh runner (no network). Timestamp tests reuse the guard-proof fixtures.
"""
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, "tools")
import fetch_guard_inputs as f  # noqa: E402
import guard_proof as gp  # noqa: E402
from tests import test_guard_proof as tgp  # noqa: E402  (shares the proof fixtures)


def no_sleep(_seconds):
    return None


class FakeGh:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, args):
        self.calls.append(args[0])
        if not self.responses:
            raise f.FetchError("no more fake responses")
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def page(key, n):
    return json.dumps({key: [{"id": i} for i in range(n)]})


class Paging(unittest.TestCase):
    def test_reads_every_page_until_a_short_page(self):
        items = f.paged(FakeGh([page("check_runs", 100), page("check_runs", 3)]), "x", "check_runs", sleep=no_sleep)
        self.assertTrue(items["complete"])
        self.assertEqual(len(items["check_runs"]), 103)

    def test_page_cap_fails_closed(self):
        original = f.MAX_PAGES
        f.MAX_PAGES = 2
        try:
            with self.assertRaises(f.FetchError) as ctx:
                f.paged(FakeGh([page("check_runs", 100), page("check_runs", 100)]), "x", "check_runs", sleep=no_sleep)
            self.assertIn("exceeds", str(ctx.exception))
        finally:
            f.MAX_PAGES = original

    def test_missing_key_fails_closed(self):
        with self.assertRaises(f.FetchError):
            f.paged(FakeGh([json.dumps({"message": "Not Found"})]), "x", "check_runs", sleep=no_sleep)


class Retries(unittest.TestCase):
    def test_transient_failure_then_success_is_retried(self):
        gh = FakeGh([f.FetchError("transient"), page("check_runs", 1)])
        out = f.gh_json(gh, "x", sleep=no_sleep)
        self.assertIn("check_runs", out)
        self.assertEqual(len(gh.calls), 2)

    def test_persistent_failure_stops_after_fixed_attempts(self):
        gh = FakeGh([f.FetchError("down")] * f.ATTEMPTS)
        with self.assertRaises(f.FetchError):
            f.gh_json(gh, "x", sleep=no_sleep)
        self.assertEqual(len(gh.calls), f.ATTEMPTS)

    def test_bad_json_is_retried_then_fails(self):
        gh = FakeGh(["not json"] * f.ATTEMPTS)
        with self.assertRaises(f.FetchError):
            f.gh_json(gh, "x", sleep=no_sleep)


class FetchFailsClosed(unittest.TestCase):
    def test_failure_on_second_page_writes_no_listing(self):
        d = Path(tempfile.mkdtemp())
        responses = [page("check_runs", 100)] + [f.FetchError("down")] * f.ATTEMPTS
        with self.assertRaises(f.FetchError):
            f.fetch(FakeGh(responses), "o/r", "a" * 40, d, sleep=no_sleep)
        self.assertFalse((d / "cr.json").exists())

    def test_complete_fetch_writes_complete_markers(self):
        d = Path(tempfile.mkdtemp())
        runs = json.dumps({"workflow_runs": [{"id": 7}]})
        jobs = json.dumps({"jobs": [{"id": 1, "name": "guard-verify"}]})
        ci = json.dumps({"content": "eA=="})
        gh = FakeGh([page("check_runs", 0), runs, ci, jobs])
        f.fetch(gh, "o/r", "a" * 40, d, sleep=no_sleep)
        self.assertTrue(json.loads((d / "cr.json").read_text())["complete"])
        self.assertTrue(json.loads((d / "runs.json").read_text())["complete"])
        self.assertTrue(json.loads((d / "jobs-7.json").read_text())["complete"])


class Timestamps(unittest.TestCase):
    def verdict_for(self, completed_at):
        d = tgp.write_case(checks=[tgp.check(completed_at=completed_at)])
        return gp.verify_guard(d, tgp.REPO, tgp.PR, tgp.HEAD, tgp.REQUIRED, tgp.BASE_DIGEST, tgp.NOW)

    def test_naive_timestamp_is_rejected(self):
        v, proof = self.verdict_for("2026-10-29T03:55:00")
        self.assertIsNone(proof)
        self.assertIn("completion time is invalid", v)

    def test_future_timestamp_is_rejected(self):
        future = (tgp.NOW + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        v, proof = self.verdict_for(future)
        self.assertIsNone(proof)
        self.assertIn("in the future", v)

    def test_small_clock_skew_is_allowed(self):
        near = (tgp.NOW + timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        v, proof = self.verdict_for(near)
        self.assertEqual(v, "PASS")

    def test_malformed_timestamp_is_rejected(self):
        v, proof = self.verdict_for("not-a-date")
        self.assertIsNone(proof)
        self.assertIn("completion time is invalid", v)

    def test_non_string_timestamp_is_rejected(self):
        v, proof = self.verdict_for(12345)
        self.assertIsNone(proof)
        self.assertIn("completion time is invalid", v)


if __name__ == "__main__":
    unittest.main()
