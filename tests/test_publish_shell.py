"""Run the real publish-step shell from gate.yml under bash, with stub gh.

GitHub runs `run:` steps with `bash --noprofile --norc -eo pipefail`. These
tests execute the exact authorize and re-authorize step bodies with that
shell, a stub `gh` that logs POSTs, and an absolute path to this Python for
`python3`. A scenario passes only if the POST log matches the expectation.
A missing bash fails the test (never a skip).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path.cwd()
BASH = r"C:\Program Files\Git\bin\bash.exe"
SHA1 = "a" * 40
SHA2 = "b" * 40
REPO = "mao2009/oss-pce-cd-bios-security-test"
GATE = yaml.safe_load((ROOT / ".github" / "workflows" / "gate.yml").read_bytes().decode("utf-8"))
STEPS = GATE["jobs"]["publish"]["steps"]


def step_run(step_id=None, name=None):
    found = [s for s in STEPS if (step_id and s.get("id") == step_id) or (name and s.get("name") == name)]
    assert len(found) == 1, (step_id, name)
    return found[0]["run"]


AUTHORIZE_RUN = step_run(step_id="authorize")
REAUTH_RUN = step_run(name="Re-authorize and publish trusted-gate check (App)")
REAUTH_ENV_NAMES = ["READ_TOKEN", "APP_TOKEN", "REPO", "PR_NUMBER", "HEAD_SHA", "EVENT_NAME", "EVAL_RESULT", "VERDICT"]


def posix(p):
    return Path(p).as_posix()


def pr_json(number=7, base_ref="main", repo=REPO, state="open", head=SHA1):
    return {
        "number": number,
        "state": state,
        "base": {"ref": base_ref, "repo": {"full_name": repo}},
        "head": {"sha": head},
    }


class Harness:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp())
        self.py = posix(sys.executable)
        self.gh_stub = self.dir / "gh_stub.sh"
        self.gh_stub.write_text(
            "#!/bin/bash\n"
            'for a in "$@"; do if [ "$a" = "POST" ]; then echo "$*" >> "$POST_LOG"; if [ "$POST_FAIL" = "1" ]; then exit 1; fi; exit 0; fi; done\n'
            'n=$(cat "$COUNTER" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$COUNTER"\n'
            'if [ "$n" -ge 2 ] && [ -s "$FIXTURE2" ]; then cat "$FIXTURE2"; else cat "$FIXTURE1"; fi\n',
            encoding="utf-8", newline="\n",
        )
        self.fixture1 = self.dir / "fixture1.json"
        self.fixture2 = self.dir / "fixture2.json"
        self.post_log = self.dir / "posted.log"
        self.counter = self.dir / "counter"
        self.github_output = self.dir / "github_output"

    def script(self, body, python=None):
        # Route the step's own commands to stubs and absolute paths; keep the body otherwise.
        py = python or self.py
        body = body.replace("python3 ", '"' + py + '" ')
        body = body.replace("gh api", '"' + posix(BASH) + '" "' + posix(self.gh_stub) + '" api')
        path = self.dir / ("step-%d.sh" % len(list(self.dir.glob("step-*.sh"))))
        path.write_text("set -eo pipefail\n" + body, encoding="utf-8", newline="\n")
        return path

    def env(self, **extra):
        env = os.environ.copy()
        env.update({
            "RUNNER_TEMP": posix(self.dir),
            "GITHUB_OUTPUT": posix(self.github_output),
            "POST_LOG": posix(self.post_log),
            "COUNTER": posix(self.counter),
            "FIXTURE1": posix(self.fixture1),
            "FIXTURE2": posix(self.fixture2),
            "GH_TOKEN": "x",
            "REPO": REPO,
            "PR_NUMBER": "7",
            "HEAD_SHA": SHA1,
            "EVENT_NAME": "pull_request_target",
            "EVAL_RESULT": "success",
            "VERDICT": "pass",
            "READ_TOKEN": "x",
            "APP_TOKEN": "app-token-placeholder",
        })
        env.update(extra)
        return env

    def run_bash(self, script, env):
        return subprocess.run(
            [BASH, "--noprofile", "--norc", "-eo", "pipefail", posix(script)],
            cwd=str(ROOT), env=env, capture_output=True, text=True,
        )

    def scenario(self, pr1, pr2=None, python=None, event_name="pull_request_target", eval_sha=SHA1, post_fail=False):
        self.fixture1.write_text(json.dumps(pr1) if pr1 is not None else "", encoding="utf-8")
        self.fixture2.write_text(json.dumps(pr2) if pr2 is not None else "", encoding="utf-8")
        for f in (self.post_log, self.counter, self.github_output):
            if f.exists():
                f.unlink()
        env = self.env(EVENT_NAME=event_name, HEAD_SHA=eval_sha, POST_FAIL="1" if post_fail else "0")
        auth = self.run_bash(self.script(AUTHORIZE_RUN, python), env)
        allow = "allow=true" in (self.github_output.read_text() if self.github_output.exists() else "")
        reauth_rc = None
        if allow:
            reauth = self.run_bash(self.script(REAUTH_RUN, python), env)
            reauth_rc = reauth.returncode
        posted = self.post_log.read_text(encoding="utf-8").splitlines() if self.post_log.exists() else []
        return {"auth_rc": auth.returncode, "allow": allow, "reauth_rc": reauth_rc, "posted": posted}


class PublishShell(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(BASH).is_file():
            raise AssertionError("bash not found at " + BASH + ": cannot execute the gate shell")

    def setUp(self):
        self.h = Harness()

    def test_good_main_pr_posts_success_once(self):
        r = self.h.scenario(pr_json(), pr_json())
        self.assertTrue(r["allow"])
        self.assertEqual(r["reauth_rc"], 0)
        self.assertEqual(len(r["posted"]), 1, r)
        self.assertIn("conclusion=success", r["posted"][0])

    def test_non_main_base_posts_nothing(self):
        r = self.h.scenario(pr_json(base_ref="gate-test/base"))
        self.assertFalse(r["allow"])
        self.assertIsNone(r["reauth_rc"])
        self.assertEqual(r["posted"], [])

    def test_base_gate_test_2_posts_nothing(self):
        r = self.h.scenario(pr_json(base_ref="gate-test/base2"))
        self.assertEqual(r["posted"], [])

    def test_other_repository_posts_nothing(self):
        r = self.h.scenario(pr_json(repo="someone/other"))
        self.assertEqual(r["posted"], [])

    def test_pr_number_mismatch_posts_nothing(self):
        r = self.h.scenario(pr_json(number=8))
        self.assertFalse(r["allow"])
        self.assertEqual(r["posted"], [])

    def test_closed_pr_posts_nothing(self):
        r = self.h.scenario(pr_json(state="closed"))
        self.assertEqual(r["posted"], [])

    def test_head_moved_between_authorize_and_repost_posts_nothing(self):
        # Authorize sees SHA1; the re-read sees SHA2 (new push). The re-authorize
        # step must exit non-zero and the POST must not happen.
        r = self.h.scenario(pr_json(head=SHA1), pr_json(head=SHA2))
        self.assertTrue(r["allow"])
        self.assertNotEqual(r["reauth_rc"], 0)
        self.assertEqual(r["posted"], [])

    def test_reread_base_changed_posts_nothing(self):
        # Authorize passes on main; the re-read shows the base changed. The
        # re-authorize step must fail and the POST must not happen.
        r = self.h.scenario(pr_json(), pr_json(base_ref="gate-test/base"))
        self.assertTrue(r["allow"])
        self.assertNotEqual(r["reauth_rc"], 0)
        self.assertEqual(r["posted"], [])

    def test_reread_state_closed_posts_nothing(self):
        r = self.h.scenario(pr_json(), pr_json(state="closed"))
        self.assertTrue(r["allow"])
        self.assertNotEqual(r["reauth_rc"], 0)
        self.assertEqual(r["posted"], [])

    def test_reread_number_changed_posts_nothing(self):
        r = self.h.scenario(pr_json(), pr_json(number=8))
        self.assertTrue(r["allow"])
        self.assertNotEqual(r["reauth_rc"], 0)
        self.assertEqual(r["posted"], [])

    def test_reread_repository_changed_posts_nothing(self):
        r = self.h.scenario(pr_json(), pr_json(repo="someone/other"))
        self.assertTrue(r["allow"])
        self.assertNotEqual(r["reauth_rc"], 0)
        self.assertEqual(r["posted"], [])

    def test_evaluated_sha_differs_from_pr_head_posts_nothing(self):
        r = self.h.scenario(pr_json(head=SHA2), eval_sha=SHA1)
        self.assertFalse(r["allow"])
        self.assertEqual(r["posted"], [])

    def test_missing_python_posts_nothing(self):
        r = self.h.scenario(pr_json(), pr_json(), python=posix(self.h.dir / "no-such-python.exe"))
        self.assertFalse(r["allow"])
        self.assertEqual(r["posted"], [])

    def test_malformed_pr_json_posts_nothing(self):
        r = self.h.scenario(None)
        self.assertEqual(r["posted"], [])

    def test_wrong_event_posts_nothing(self):
        r = self.h.scenario(pr_json(), pr_json(), event_name="pull_request")
        self.assertFalse(r["allow"])
        self.assertEqual(r["posted"], [])

    def test_post_failure_is_not_reported_as_success(self):
        # The POST itself fails (gh api exits 1). The step must fail; no success is recorded.
        r = self.h.scenario(pr_json(), pr_json(), post_fail=True)
        self.assertTrue(r["allow"])
        self.assertNotEqual(r["reauth_rc"], 0)
        self.assertEqual(len(r["posted"]), 1)

    def test_reauthorize_step_has_no_error_suppression(self):
        # Any shell operator on the re-authorize or post command could swallow a failure.
        self.assertNotIn("||", REAUTH_RUN)
        post_step = [s for s in STEPS if s.get("name") == "Re-authorize and publish trusted-gate check (App)"][0]
        self.assertNotIn("continue-on-error", post_step)


if __name__ == "__main__":
    unittest.main()
