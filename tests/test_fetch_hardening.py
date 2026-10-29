"""Hardening: listing completeness, bounded paging and retries, stale files, timestamps, reruns.

Fetch tests use a fake gh runner (no network). Proof tests reuse the guard-proof fixtures.
The expected values below are written out literally, not read back from implementation constants.
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

APP_ID = 15368  # GitHub Actions app id, written out literally
SKEW_MINUTES = 3  # the documented future-date allowance, written out literally


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


def page(key, ids, total=None):
    items = [{"id": i} for i in ids]
    return json.dumps({key: items, "total_count": len(ids) if total is None else total})


class Paging(unittest.TestCase):
    def test_reads_every_page_and_verifies_total(self):
        p1 = page("check_runs", range(100), total=103)
        p2 = page("check_runs", range(100, 103), total=103)
        out = f.paged(FakeGh([p1, p2]), "x", "check_runs", sleep=no_sleep)
        self.assertTrue(out["complete"])
        self.assertEqual(len(out["check_runs"]), 103)
        self.assertEqual(out["total_count"], 103)

    def test_total_changing_mid_listing_fails(self):
        p1 = page("check_runs", range(100), total=103)
        p2 = page("check_runs", range(100, 103), total=104)
        with self.assertRaises(f.FetchError) as ctx:
            f.paged(FakeGh([p1, p2]), "x", "check_runs", sleep=no_sleep)
        self.assertIn("changed while paging", str(ctx.exception))

    def test_count_below_total_fails(self):
        # total says 150, but the listing ends after 103 items.
        p1 = page("check_runs", range(100), total=150)
        p2 = page("check_runs", range(100, 103), total=150)
        with self.assertRaises(f.FetchError) as ctx:
            f.paged(FakeGh([p1, p2]), "x", "check_runs", sleep=no_sleep)
        self.assertIn("does not match total_count", str(ctx.exception))

    def test_duplicate_items_fail(self):
        p1 = page("check_runs", range(100), total=103)
        p2 = page("check_runs", [0, 1, 2], total=103)
        with self.assertRaises(f.FetchError) as ctx:
            f.paged(FakeGh([p1, p2]), "x", "check_runs", sleep=no_sleep)
        self.assertIn("duplicate", str(ctx.exception))

    def test_page_cap_fails_closed(self):
        original = f.MAX_PAGES
        f.MAX_PAGES = 2
        try:
            with self.assertRaises(f.FetchError) as ctx:
                f.paged(FakeGh([page("check_runs", range(100), 1000), page("check_runs", range(100, 200), 1000)]), "x", "check_runs", sleep=no_sleep)
            self.assertIn("exceeds", str(ctx.exception))
        finally:
            f.MAX_PAGES = original

    def test_missing_total_count_fails(self):
        with self.assertRaises(f.FetchError):
            f.paged(FakeGh([json.dumps({"check_runs": []})]), "x", "check_runs", sleep=no_sleep)


class Retries(unittest.TestCase):
    def test_transient_failure_then_success_is_retried(self):
        gh = FakeGh([f.FetchError("transient"), page("check_runs", range(1))])
        out = f.gh_json(gh, "x", sleep=no_sleep)
        self.assertIn("check_runs", out)
        self.assertEqual(len(gh.calls), 2)

    def test_persistent_failure_stops_after_three_attempts(self):
        gh = FakeGh([f.FetchError("down")] * 3)
        with self.assertRaises(f.FetchError):
            f.gh_json(gh, "x", sleep=no_sleep)
        self.assertEqual(len(gh.calls), 3)


class FetchFailsClosed(unittest.TestCase):
    def test_failure_on_second_page_writes_no_listing(self):
        d = Path(tempfile.mkdtemp())
        responses = [page("check_runs", range(100), total=200)] + [f.FetchError("down")] * 3
        with self.assertRaises(f.FetchError):
            f.fetch(FakeGh(responses), "o/r", "a" * 40, d, sleep=no_sleep)
        self.assertFalse((d / "cr.json").exists())

    def test_stale_files_from_an_earlier_fetch_are_removed(self):
        d = Path(tempfile.mkdtemp())
        (d / "cr.json").write_text(json.dumps({"check_runs": [], "complete": True, "total_count": 0}), encoding="utf-8")
        (d / "jobs-99.json").write_text(json.dumps({"jobs": [], "complete": True, "total_count": 0}), encoding="utf-8")
        with self.assertRaises(f.FetchError):
            f.fetch(FakeGh([f.FetchError("down")] * 3), "o/r", "a" * 40, d, sleep=no_sleep)
        self.assertFalse((d / "cr.json").exists())
        self.assertFalse((d / "jobs-99.json").exists())

    def test_complete_fetch_writes_complete_and_counted_listings(self):
        d = Path(tempfile.mkdtemp())
        runs = json.dumps({"workflow_runs": [{"id": 7}], "total_count": 1})
        jobs = json.dumps({"jobs": [{"id": 1, "name": "guard-verify"}], "total_count": 1})
        ci = json.dumps({"content": "eA=="})
        gh = FakeGh([page("check_runs", [], total=0), runs, ci, jobs])
        f.fetch(gh, "o/r", "a" * 40, d, sleep=no_sleep)
        cr_doc = json.loads((d / "cr.json").read_text())
        self.assertTrue(cr_doc["complete"])
        self.assertEqual(cr_doc["total_count"], 0)
        self.assertTrue(json.loads((d / "jobs-7.json").read_text())["complete"])


class Timestamps(unittest.TestCase):
    def verdict_for(self, completed_at):
        d = tgp.write_case(checks=[tgp.check(completed_at=completed_at)])
        return gp.verify_guard(d, tgp.REPO, tgp.PR, tgp.HEAD, tgp.REQUIRED, tgp.BASE_DIGEST, tgp.NOW)

    def stamp(self, minutes):
        return (tgp.NOW + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_three_minutes_ahead_is_allowed(self):
        self.assertEqual(self.verdict_for(self.stamp(SKEW_MINUTES))[0], "PASS")

    def test_just_over_three_minutes_ahead_is_rejected(self):
        future = (tgp.NOW + timedelta(minutes=SKEW_MINUTES, seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        v, proof = self.verdict_for(future)
        self.assertIsNone(proof)
        self.assertIn("in the future", v)

    def test_naive_timestamp_is_rejected(self):
        v, proof = self.verdict_for("2026-10-29T03:55:00")
        self.assertIsNone(proof)
        self.assertIn("completion time is invalid", v)

    def test_malformed_timestamp_is_rejected(self):
        v, proof = self.verdict_for("not-a-date")
        self.assertIsNone(proof)
        self.assertIn("completion time is invalid", v)

    def test_invalid_offset_is_rejected(self):
        v, proof = self.verdict_for("2026-10-29T03:55:00+25:00")
        self.assertIsNone(proof)
        self.assertIn("completion time is invalid", v)

    def test_non_string_timestamp_is_rejected(self):
        v, proof = self.verdict_for(12345)
        self.assertIsNone(proof)
        self.assertIn("completion time is invalid", v)


class Reruns(unittest.TestCase):
    def verdict_for_checks(self, checks):
        d = tgp.write_case(checks=checks)
        return gp.verify_guard(d, tgp.REPO, tgp.PR, tgp.HEAD, tgp.REQUIRED, tgp.BASE_DIGEST, tgp.NOW)

    def test_in_progress_rerun_blocks_an_older_success(self):
        older_success = tgp.check(completed_at=(tgp.NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        running = tgp.check(id=tgp.CHECK + 1, status="in_progress", conclusion=None, completed_at=None)
        v, proof = self.verdict_for_checks([older_success, running])
        self.assertIsNone(proof)
        self.assertTrue(v.startswith("PENDING"), v)

    def test_queued_rerun_blocks_an_older_success(self):
        older_success = tgp.check(completed_at=(tgp.NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        queued = tgp.check(id=tgp.CHECK + 1, status="queued", conclusion=None, completed_at=None)
        v, proof = self.verdict_for_checks([older_success, queued])
        self.assertTrue(v.startswith("PENDING"), v)

    def test_latest_cancelled_is_not_success(self):
        older_success = tgp.check(completed_at=(tgp.NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        cancelled = tgp.check(id=tgp.CHECK + 1, conclusion="cancelled", completed_at=tgp.RECENT)
        v, proof = self.verdict_for_checks([older_success, cancelled])
        self.assertIsNone(proof)
        self.assertIn("conclusion is cancelled", v)

    def test_latest_timed_out_is_not_success(self):
        older_success = tgp.check(completed_at=(tgp.NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        timed_out = tgp.check(id=tgp.CHECK + 1, conclusion="timed_out", completed_at=tgp.RECENT)
        v, proof = self.verdict_for_checks([older_success, timed_out])
        self.assertIsNone(proof)
        self.assertIn("conclusion is timed_out", v)

    def test_completed_without_time_is_rejected(self):
        v, proof = self.verdict_for_checks([tgp.check(completed_at=None)])
        self.assertIsNone(proof)


if __name__ == "__main__":
    unittest.main()
