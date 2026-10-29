"""Publish authorization: the App token and the check post require every condition.

Each negative changes exactly one condition from a known-good PR, so a failure
points at that condition. Config tests parse gate.yml as YAML.
"""
import copy
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, "tools")
import trusted_gate as g  # noqa: E402

REPO = "mao2009/oss-pce-cd-bios-security-test"
SHA = "c" * 40
EVENT = "pull_request_target"
GOOD = {
    "number": 7,
    "state": "open",
    "base": {"ref": "main", "repo": {"full_name": REPO}},
    "head": {"sha": SHA},
}


NUMBER = "7"


def authorize(pr, repo=REPO, eval_sha=SHA, event=EVENT, number=NUMBER):
    return g.authorize_publish(pr, repo, eval_sha, event, number)


def mutated(fn):
    pr = copy.deepcopy(GOOD)
    fn(pr)
    return pr


class Allow(unittest.TestCase):
    def test_main_base_open_current_head_is_allowed(self):
        self.assertEqual(authorize(GOOD)[0], True)


class Deny(unittest.TestCase):
    def assertDenied(self, allowed_reason, **kwargs):
        allowed, reason = authorize(**kwargs)
        self.assertFalse(allowed)
        self.assertIn(allowed_reason, reason)

    def test_non_main_base_is_denied(self):
        # The bypass: a PR whose base is a branch the attacker controls.
        pr = mutated(lambda p: p["base"].update(ref="gate-test/base"))
        self.assertDenied("base ref is not main", pr=pr)

    def test_fork_or_other_repository_base_is_denied(self):
        pr = mutated(lambda p: p["base"]["repo"].update(full_name="someone/other-fork"))
        self.assertDenied("base repository", pr=pr)

    def test_expected_repo_mismatch_is_denied(self):
        self.assertDenied("base repository", pr=GOOD, repo="mao2009/oss-pce-cd-bios")

    def test_closed_pr_is_denied(self):
        self.assertDenied("not open", pr=mutated(lambda p: p.update(state="closed")))

    def test_head_moved_since_evaluation_is_denied(self):
        pr = mutated(lambda p: p["head"].update(sha="d" * 40))
        self.assertDenied("head moved", pr=pr)

    def test_wrong_event_is_denied(self):
        self.assertDenied("event is not", pr=GOOD, event="pull_request")

    def test_pr_number_mismatch_is_denied(self):
        # The PR JSON is for PR 8, but the event is PR 7 (same head SHA).
        pr = mutated(lambda p: p.update(number=8))
        self.assertDenied("PR number does not match", pr=pr)

    def test_event_number_not_numeric_is_denied(self):
        self.assertDenied("PR number does not match", pr=GOOD, number="7;rm")

    def test_event_number_missing_is_denied(self):
        self.assertDenied("PR number does not match", pr=GOOD, number="")

    def test_malformed_evaluated_sha_is_denied(self):
        self.assertDenied("malformed", pr=GOOD, eval_sha="C" * 40)

    def test_missing_base_field_is_denied(self):
        pr = mutated(lambda p: p.pop("base"))
        self.assertDenied("missing a required field", pr=pr)

    def test_missing_head_field_is_denied(self):
        pr = mutated(lambda p: p.pop("head"))
        self.assertDenied("missing a required field", pr=pr)

    def test_non_mapping_pr_is_denied(self):
        self.assertDenied("missing a required field", pr=None)


class AuthorizeCli(unittest.TestCase):
    def test_cli_denies_with_exit_1_for_non_main_base(self):
        import json
        import subprocess
        import tempfile

        pr = mutated(lambda p: p["base"].update(ref="gate-test/base"))
        path = Path(tempfile.mkdtemp()) / "pr.json"
        path.write_text(json.dumps(pr), encoding="utf-8")
        r = subprocess.run(
            [sys.executable, "tools/trusted_gate.py", "authorize", str(path), REPO, SHA, EVENT, NUMBER],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertTrue(r.stdout.startswith("DENY"), r.stdout)

    def test_cli_allows_with_exit_0(self):
        import json
        import subprocess
        import tempfile

        path = Path(tempfile.mkdtemp()) / "pr.json"
        path.write_text(json.dumps(GOOD), encoding="utf-8")
        r = subprocess.run(
            [sys.executable, "tools/trusted_gate.py", "authorize", str(path), REPO, SHA, EVENT, NUMBER],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("ALLOW"), r.stdout)


class GateConfig(unittest.TestCase):
    def setUp(self):
        doc = yaml.safe_load(Path(".github/workflows/gate.yml").read_bytes().decode("utf-8"))
        self.steps = doc["jobs"]["publish"]["steps"]

    def step(self, step_id=None, name=None):
        found = [s for s in self.steps if (step_id and s.get("id") == step_id) or (name and s.get("name") == name)]
        self.assertEqual(len(found), 1, (step_id, name))
        return found[0]

    def test_app_token_requires_authorization(self):
        self.assertEqual(self.step(step_id="app")["if"], "steps.authorize.outputs.allow == 'true'")

    def test_post_requires_authorization_and_reauthorizes(self):
        post = self.step(name="Re-authorize and publish trusted-gate check (App)")
        self.assertEqual(post["if"], "steps.authorize.outputs.allow == 'true'")
        run = post["run"]
        self.assertIn('trusted_gate.py authorize "$RUNNER_TEMP/pr-2.json"', run)
        self.assertLess(run.index("trusted_gate.py authorize"), run.index("check-runs"))

    def test_authorize_step_runs_before_any_app_token(self):
        names = [s.get("id") or s.get("name") for s in self.steps]
        self.assertLess(names.index("authorize"), names.index("app"))

    def test_app_token_only_in_the_post_step(self):
        for s in self.steps:
            if s.get("id") == "app":
                continue
            if "APP_TOKEN" in str(s.get("env", {})) or "steps.app.outputs" in str(s.get("env", {})):
                self.assertEqual(s.get("name"), "Re-authorize and publish trusted-gate check (App)")


if __name__ == "__main__":
    unittest.main()
