"""Worker B: end-to-end run of the gate CLI (subprocess), as gate.yml invokes it."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path.cwd()
GATE_CLI = REPO / "tools" / "trusted_gate.py"
SHA = "a" * 40
OTHER = "b" * 40


def run_cli(*args, cwd=REPO):
    return subprocess.run([sys.executable, str(GATE_CLI), *args], capture_output=True, text=True, cwd=cwd)


def candidate_from_repo(mutate=None):
    root = Path(tempfile.mkdtemp())
    shutil.copytree(REPO / ".github", root / ".github")
    if mutate:
        mutate(root / ".github" / "workflows" / "ci.yml")
    return root


class GateCli(unittest.TestCase):
    def test_pass_on_unmodified_candidate(self):
        cand = candidate_from_repo()
        r = run_cli(str(cand), ".", SHA, SHA)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout.strip(), "PASS")

    def test_guard_removed_fails_with_exit_1(self):
        def strip_guard(p):
            text = p.read_bytes().decode("utf-8")
            p.write_bytes(text.split("  guard-verify:")[0].rstrip().encode("utf-8") + b"\n")
        cand = candidate_from_repo(strip_guard)
        r = run_cli(str(cand), ".", SHA, SHA)
        self.assertEqual(r.returncode, 1)
        self.assertTrue(r.stdout.startswith("FAIL:"), r.stdout)

    def test_head_mismatch_fails_with_exit_1(self):
        cand = candidate_from_repo()
        r = run_cli(str(cand), ".", SHA, OTHER)
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not match", r.stdout)

    def test_wrong_argument_count_exits_2(self):
        self.assertEqual(run_cli(".", SHA).returncode, 2)

    def test_missing_pyyaml_does_not_pass(self):
        # Simulate a runner without PyYAML: importing yaml must fail the gate.
        cand = candidate_from_repo()
        code = (
            "import sys, runpy; sys.modules['yaml'] = None; "
            "sys.argv = ['trusted_gate.py', %r, '.', %r, %r]; "
            "runpy.run_path(%r, run_name='__main__')" % (str(cand), SHA, SHA, str(GATE_CLI))
        )
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("PASS", r.stdout)

    def test_publish_mode_is_fail_closed(self):
        self.assertEqual(run_cli("publish", "success", "pass", SHA, OTHER).stdout.strip(), "failure")
        self.assertEqual(run_cli("publish", "success", "pass", SHA, SHA).stdout.strip(), "success")


class GateWorkflowConfig(unittest.TestCase):
    def setUp(self):
        self.doc = yaml.safe_load((REPO / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8").replace("\r\n", "\n"))

    def test_evaluate_runs_four_argument_cli(self):
        runs = [s.get("run", "") for s in self.doc["jobs"]["evaluate"]["steps"]]
        calls = [ln for r in runs for ln in r.splitlines() if "tools/trusted_gate.py" in ln]
        self.assertEqual(len(calls), 1, calls)
        self.assertIn("tools/trusted_gate.py candidate . ", calls[0])

    def test_pyyaml_installed_from_pinned_requirements_in_base(self):
        runs = [s.get("run", "") for s in self.doc["jobs"]["evaluate"]["steps"]]
        installs = [r for r in runs if "pip install" in r]
        self.assertEqual(len(installs), 1)
        self.assertIn("-r tools/requirements-lint.txt", installs[0])
        req = (REPO / "tools" / "requirements-lint.txt").read_text(encoding="utf-8")
        self.assertIn("pyyaml==6.0.3", req)

    def test_app_identity_and_check_name_are_pinned(self):
        step = [s for s in self.doc["jobs"]["publish"]["steps"] if s.get("id") == "app"][0]
        self.assertEqual(step["with"]["app-id"], 5519582)
        post_lines = [ln for s in self.doc["jobs"]["publish"]["steps"] for ln in s.get("run", "").splitlines() if "check-runs" in ln]
        self.assertEqual(len(post_lines), 1)
        self.assertIn("-f name=trusted-gate", "\n".join(s.get("run", "") for s in self.doc["jobs"]["publish"]["steps"]))


if __name__ == "__main__":
    unittest.main()
