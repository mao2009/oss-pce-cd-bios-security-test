import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "tools")
import trusted_gate as g  # noqa: E402

CI = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
SHA = "a" * 40
OTHER = "b" * 40


def workspace(ci_text):
    root = Path(tempfile.mkdtemp())
    (root / ".github" / "workflows").mkdir(parents=True)
    if ci_text is not None:
        (root / ".github" / "workflows" / "ci.yml").write_text(ci_text, encoding="utf-8")
    return str(root)


class TrustedGateTest(unittest.TestCase):
    def test_control_passes(self):
        self.assertEqual(g.verdict(workspace(CI), SHA, SHA), "PASS")

    def test_checked_out_sha_mismatch_fails(self):
        self.assertIn("does not match", g.verdict(workspace(CI), SHA, OTHER))

    def test_guard_removed_fails(self):
        self.assertIn("missing", g.verdict(workspace(CI.split("  guard-verify:")[0]), SHA, SHA))

    def test_guard_if_false_fails(self):
        ci = CI.replace("  guard-verify:\n", "  guard-verify:\n    if: false\n")
        self.assertIn("if:", g.verdict(workspace(ci), SHA, SHA))

    def test_ci_deleted_fails(self):
        self.assertIn("missing", g.verdict(workspace(None), SHA, SHA))

    def test_guard_needs_changed_fails(self):
        ci = CI.replace("needs: verify", "needs: []")
        self.assertIn("changed", g.verdict(workspace(ci), SHA, SHA))


if __name__ == "__main__":
    unittest.main()
