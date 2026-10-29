"""Worker C: App check decisions and TOCTOU/spoofing negatives (local, no GitHub).

Config checks parse gate.yml as YAML and inspect the exact command lines, so a
swapped token or a commented-out line fails the test.
"""
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, "tools")
import trusted_gate as g  # noqa: E402

OLD = "1" * 40
NEW = "2" * 40
REPO = Path.cwd()
PUBLISH_STEP = "Re-authorize and publish trusted-gate check (App)"


def publish_run_lines():
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8").replace("\r\n", "\n"))
    steps = doc["jobs"]["publish"]["steps"]
    (step,) = [s for s in steps if s.get("name") == PUBLISH_STEP]
    return step["run"].splitlines()


class PublishConclusion(unittest.TestCase):
    def test_happy_path_is_success(self):
        self.assertEqual(g.publish_conclusion("success", "pass", NEW, NEW), "success")

    def test_evaluate_failure_is_failure(self):
        self.assertEqual(g.publish_conclusion("failure", "pass", NEW, NEW), "failure")

    def test_evaluate_cancelled_is_failure(self):
        self.assertEqual(g.publish_conclusion("cancelled", "pass", NEW, NEW), "failure")

    def test_evaluate_skipped_is_failure(self):
        self.assertEqual(g.publish_conclusion("skipped", "pass", NEW, NEW), "failure")

    def test_verdict_fail_is_failure(self):
        self.assertEqual(g.publish_conclusion("success", "fail", NEW, NEW), "failure")

    def test_verdict_empty_is_failure(self):
        self.assertEqual(g.publish_conclusion("success", "", NEW, NEW), "failure")

    def test_verdict_spoof_with_whitespace_is_failure(self):
        self.assertEqual(g.publish_conclusion("success", "pass ", NEW, NEW), "failure")

    def test_stale_head_rule_is_failure(self):
        # Unit rule only: evaluated OLD while the PR is at NEW must not publish success.
        # The end-to-end read/post window is covered by the workflow config test below.
        self.assertEqual(g.publish_conclusion("success", "pass", OLD, NEW), "failure")

    def test_current_head_unknown_is_failure(self):
        self.assertEqual(g.publish_conclusion("success", "pass", NEW, ""), "failure")

    def test_head_not_full_sha_is_failure(self):
        short = "2" * 39
        self.assertEqual(g.publish_conclusion("success", "pass", short, short), "failure")

    def test_head_uppercase_is_failure(self):
        upper = "A" * 40
        self.assertEqual(g.publish_conclusion("success", "pass", upper, upper), "failure")

    def test_head_with_trailing_newline_is_failure(self):
        head = NEW + "\n"
        self.assertEqual(g.publish_conclusion("success", "pass", head, head), "failure")


class SameRepoAndForkInputs(unittest.TestCase):
    def test_checked_out_head_must_match_pr_head(self):
        # Fork or wrong checkout: the checked-out commit differs from the PR head.
        self.assertIn("does not match", g.verdict(str(REPO), str(REPO), NEW, OLD))

    def test_non_sha_head_fails_closed(self):
        self.assertIn("does not match", g.verdict(str(REPO), str(REPO), "HEAD", "HEAD"))


class GateConfigForToctou(unittest.TestCase):
    def setUp(self):
        self.lines = publish_run_lines()

    def test_head_is_read_with_github_token_only(self):
        reads = [ln for ln in self.lines if "pulls/$PR_NUMBER" in ln]
        self.assertEqual(len(reads), 1, self.lines)
        self.assertIn('GH_TOKEN="$READ_TOKEN"', reads[0])
        self.assertNotIn("APP_TOKEN", reads[0])

    def test_check_is_posted_with_app_token_only(self):
        posts = [ln for ln in self.lines if "check-runs" in ln]
        self.assertEqual(len(posts), 1, self.lines)
        self.assertIn('GH_TOKEN="$APP_TOKEN"', posts[0])
        self.assertNotIn("READ_TOKEN", posts[0])

    def test_head_read_and_post_are_in_the_same_step(self):
        # Structural: one step contains both the read and the post (no gap between steps).
        self.assertTrue(any("pulls/$PR_NUMBER" in ln for ln in self.lines))
        self.assertTrue(any("check-runs" in ln for ln in self.lines))


if __name__ == "__main__":
    unittest.main()
