import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "tools")
import trusted_gate as g  # noqa: E402

CI = Path("tests/fixtures/ci_stub.yml").read_text(encoding="utf-8")   # stub base, not the live ci.yml (see test_workflow_lint)
GATE = Path(".github/workflows/gate.yml").read_bytes().decode("utf-8")
# The base checkout the gate compares against: the stub ci.yml (what these tests were written for) and the real gate.yml.
BASE_ROOT = tempfile.mkdtemp(prefix="base-root-")
(Path(BASE_ROOT) / ".github" / "workflows").mkdir(parents=True)
(Path(BASE_ROOT) / ".github" / "workflows" / "ci.yml").write_bytes(CI.encode("utf-8"))
(Path(BASE_ROOT) / ".github" / "workflows" / "gate.yml").write_bytes(GATE.encode("utf-8"))
SHA = "a" * 40
OTHER = "b" * 40


def candidate(ci_text, gate_text=GATE):
    root = Path(tempfile.mkdtemp())
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True)
    if ci_text is not None:
        (wf / "ci.yml").write_bytes(ci_text.encode("utf-8"))
    (wf / "gate.yml").write_bytes(gate_text.encode("utf-8"))
    return str(root)


class TrustedGateCli(unittest.TestCase):
    def test_control_passes(self):
        self.assertEqual(g.verdict(candidate(CI), BASE_ROOT, SHA, SHA), "PASS")

    def test_head_mismatch_fails(self):
        self.assertIn("does not match", g.verdict(candidate(CI), BASE_ROOT, SHA, OTHER))

    def test_invalid_sha_fails(self):
        self.assertIn("does not match", g.verdict(candidate(CI), BASE_ROOT, "x", "x"))

    def test_guard_removed_fails(self):
        self.assertIn("missing", g.verdict(candidate(CI.split("  guard-verify:")[0]), BASE_ROOT, SHA, SHA))

    def test_guard_if_false_fails(self):
        self.assertIn("changed", g.verdict(candidate(CI.replace("  guard-verify:\n", "  guard-verify:\n    if: false\n")), BASE_ROOT, SHA, SHA))

    def test_ci_deleted_fails(self):
        self.assertIn("removed or renamed", g.verdict(candidate(None), BASE_ROOT, SHA, SHA))

    def test_candidate_gate_tamper_fails(self):
        self.assertIn("gate.yml changed", g.verdict(candidate(CI, GATE + "\n# tamper\n"), BASE_ROOT, SHA, SHA))

    def test_reviewer_text_injection_fails(self):
        # Reviewer CRITICAL 2: fake guard text inside a block scalar, real guard disabled.
        fake = "name: |\n  guard-verify:\n    needs: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo guard\non:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo verify\n  guard-verify:\n    if: ${{ false }}\n    needs: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo guard\n"
        self.assertIn("guard-verify job changed", g.verdict(candidate(fake), BASE_ROOT, SHA, SHA))

    def test_base_without_guard_fails_closed(self):
        broken = Path(tempfile.mkdtemp())
        (broken / ".github" / "workflows").mkdir(parents=True)
        (broken / ".github" / "workflows" / "ci.yml").write_bytes(CI.replace("  guard-verify:", "  guard-verify-x:").encode("utf-8"))
        (broken / ".github" / "workflows" / "gate.yml").write_bytes(GATE.encode("utf-8"))
        self.assertIn("base guard-verify job missing", g.verdict(candidate(CI), str(broken), SHA, SHA))


if __name__ == "__main__":
    unittest.main()
