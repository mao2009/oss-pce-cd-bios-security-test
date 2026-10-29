"""Worker C: App check decisions and TOCTOU/spoofing negatives (local, no GitHub)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "tools")
import trusted_gate as g  # noqa: E402

OLD = "1" * 40
NEW = "2" * 40
REPO = Path.cwd()


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

    def test_stale_head_success_not_reused(self):
        # Evaluated OLD, PR moved to NEW during the run: must not publish success for OLD.
        self.assertEqual(g.publish_conclusion("success", "pass", OLD, NEW), "failure")

    def test_current_head_unknown_is_failure(self):
        self.assertEqual(g.publish_conclusion("success", "pass", NEW, ""), "failure")

    def test_head_not_full_sha_is_failure(self):
        short = "2" * 39
        self.assertEqual(g.publish_conclusion("success", "pass", short, short), "failure")

    def test_head_uppercase_is_failure(self):
        upper = "A" * 40
        self.assertEqual(g.publish_conclusion("success", "pass", upper, upper), "failure")


class SameRepoAndForkInputs(unittest.TestCase):
    def test_checked_out_head_must_match_pr_head(self):
        # Fork or wrong checkout: the checked-out commit differs from the PR head.
        self.assertIn("does not match", g.verdict(str(REPO), str(REPO), NEW, OLD))

    def test_non_sha_head_fails_closed(self):
        self.assertIn("does not match", g.verdict(str(REPO), str(REPO), "HEAD", "HEAD"))


class GateConfigForToctou(unittest.TestCase):
    def setUp(self):
        self.gate = (REPO / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")

    def test_publish_reads_head_in_same_step_as_post(self):
        # The current head is read in the same step that posts the check.
        step = self.gate.split("- name: Read current PR head")[1]
        self.assertIn("pulls/$PR_NUMBER", step)
        self.assertIn("check-runs", step)

    def test_app_token_is_used_only_for_the_post(self):
        step = self.gate.split("- name: Read current PR head")[1]
        self.assertIn('GH_TOKEN="$READ_TOKEN"', step)
        self.assertIn('GH_TOKEN="$APP_TOKEN"', step)


if __name__ == "__main__":
    unittest.main()
