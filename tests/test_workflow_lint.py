import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "tools")
import workflow_lint as w  # noqa: E402

BASE = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
GATE = Path(".github/workflows/gate.yml").read_text(encoding="utf-8")
SHA = "11d5960a326750d5838078e36cf38b85af677262"
NIGHTLY = "name: nightly\non:\n  schedule:\n    - cron: '0 3 * * *'\n  workflow_dispatch:\njobs:\n  nightly:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo nightly\n"
BASE_FILES = {"ci.yml": BASE, "nightly.yml": NIGHTLY, "gate.yml": GATE}


def write_tree(files):
    root = Path(tempfile.mkdtemp())
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True)
    for name, text in files.items():
        if text is None:
            continue
        target = root / name if name.startswith(".github/") else wf / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def base_baseline():
    return w.baseline_from_tree(write_tree(BASE_FILES))


BASELINE = base_baseline()


def check(overrides=None, baseline=None):
    files = dict(BASE_FILES)
    files.update(overrides or {})
    return w.check_tree(write_tree(files), baseline or BASELINE)


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


class Negative(unittest.TestCase):
    def assertRejects(self, needle, overrides=None, baseline=None):
        with self.assertRaises(w.LintError) as ctx:
            check(overrides, baseline)
        self.assertIn(needle, str(ctx.exception))

    def ci(self, text):
        return {"ci.yml": text}

    # Original 17 cases (re-pointed at the derived baseline)
    def test_01_duplicate_on(self):
        self.assertRejects("duplicate key: 'on'", self.ci("on: push\n" + BASE))

    def test_02_duplicate_jobs(self):
        self.assertRejects("duplicate key: 'jobs'", self.ci(BASE + "jobs:\n  x:\n    runs-on: x\n"))

    def test_03_duplicate_steps(self):
        text = replace_once(BASE, "    needs: verify\n", "    needs: verify\n    steps:\n      - run: echo x\n")
        self.assertRejects("duplicate key: 'steps'", self.ci(text))

    def test_04_duplicate_run(self):
        text = replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n        run: echo two\n")
        self.assertRejects("duplicate key: 'run'", self.ci(text))

    def test_05_on_disabled(self):
        text = replace_once(BASE, "on:\n  pull_request:\n  push:\n    branches: [main]\n", "on: []\n")
        self.assertRejects("triggers changed", self.ci(text))

    def test_06_guard_if_false(self):
        text = replace_once(BASE, "  guard-verify:\n", "  guard-verify:\n    if: false\n")
        self.assertRejects("guard-verify job changed", self.ci(text))

    def test_07_guard_renamed(self):
        text = replace_once(BASE, "  guard-verify:\n", "  guard-verify-x:\n")
        self.assertRejects("guard-verify job missing", self.ci(text))

    def test_08_pull_request_trigger_removed(self):
        text = replace_once(BASE, "  pull_request:\n", "")
        self.assertRejects("triggers changed", self.ci(text))

    def test_09_merge_key(self):
        text = replace_once(BASE, "  verify:\n", "  verify:\n    <<: {runs-on: x}\n")
        self.assertRejects("merge key", self.ci(text))

    def test_10_anchor_alias(self):
        text = replace_once(BASE, "    runs-on: ubuntu-24.04\n    steps:\n      - run: echo verify", "    runs-on: &r ubuntu-24.04\n    steps:\n      - run: echo verify")
        self.assertRejects("anchor", self.ci(text))

    def test_11_guard_shell_changed(self):
        text = replace_once(BASE, "  guard-verify:\n", "  guard-verify:\n    defaults:\n      run:\n        shell: sh\n")
        self.assertRejects("guard-verify job changed", self.ci(text))

    def test_12_guard_checkout_ref_changed(self):
        text = replace_once(BASE, "      - run: echo guard\n", "      - uses: actions/checkout@" + SHA + "\n        with:\n          ref: main\n")
        self.assertRejects("guard-verify job changed", self.ci(text))

    def test_13_guard_uses_replaced(self):
        text = replace_once(BASE, "      - run: echo guard\n", "      - uses: actions/checkout@" + SHA + "\n")
        self.assertRejects("guard-verify job changed", self.ci(text))

    def test_14_new_publish_job(self):
        text = BASE + ("  publish:\n    runs-on: x\n    steps:\n      - uses: actions/upload-artifact@" + SHA + "\n        with:\n          name: x\n          path: x\n")
        self.assertRejects("unapproved", self.ci(text))

    def test_15_composite_action(self):
        with self.assertRaises(w.LintError) as ctx:
            check({".github/actions/x/action.yml": "name: x\n"})
        self.assertIn("composite", str(ctx.exception))

    def test_16_gh_release_in_run(self):
        text = BASE + "  rel:\n    runs-on: x\n    steps:\n      - run: gh release create v1 x\n"
        self.assertRejects("unapproved publish route", self.ci(text))

    def test_18_ambiguous_bool_key(self):
        text = replace_once(BASE, "  verify:\n", "  verify:\n    yes:\n      x: 1\n")
        self.assertRejects("ambiguous bool key", self.ci(text))

    # Workflow set and trust-boundary cases
    def test_19_nightly_deleted(self):
        self.assertRejects("removed or renamed", {"nightly.yml": None})

    def test_20_workflow_added(self):
        self.assertRejects("added or renamed", {"extra.yml": "on: push\njobs:\n  x:\n    runs-on: x\n    steps: []\n"})

    def test_21_ci_renamed(self):
        self.assertRejects("removed or renamed", {"ci.yml": None, "ci2.yml": BASE})

    def test_22_nightly_schedule_removed(self):
        self.assertRejects("triggers changed", {"nightly.yml": NIGHTLY.replace("  schedule:\n    - cron: '0 3 * * *'\n", "")})

    def test_23_nightly_disabled(self):
        self.assertRejects("triggers changed", {"nightly.yml": NIGHTLY.replace("on:\n  schedule:\n    - cron: '0 3 * * *'\n  workflow_dispatch:\n", "on: []\n")})

    def test_24_baseline_publish_route_dropped(self):
        baseline = dict(BASELINE, publish=["ci.yml:verify"])
        self.assertRejects("baseline publish route removed", None, baseline)

    def test_25_candidate_cannot_extend_baseline(self):
        text = BASE + ("  publish:\n    runs-on: x\n    steps:\n      - uses: actions/upload-artifact@" + SHA + "\n        with:\n          name: x\n          path: x\n")
        self.assertRejects("unapproved", self.ci(text))

    def test_26_fake_guard_in_block_scalar(self):
        # Reviewer CRITICAL 2: literal "guard-verify:" text inside name:, real job disabled.
        text = "name: |\n  guard-verify:\n    needs: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo guard\non:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo verify\n  guard-verify:\n    if: ${{ false }}\n    needs: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo guard\n"
        self.assertRejects("guard-verify job changed", self.ci(text))

    def test_27_job_if_expression(self):
        text = replace_once(BASE, "  verify:\n", "  verify:\n    if: github.event_name == 'push'\n")
        self.assertRejects("unapproved flag", self.ci(text))

    def test_28_step_if_false(self):
        text = replace_once(BASE, "      - run: echo verify\n", "      - if: false\n        run: echo verify\n")
        self.assertRejects("unapproved flag", self.ci(text))

    def test_29_continue_on_error(self):
        text = replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n        continue-on-error: true\n")
        self.assertRejects("unapproved flag", self.ci(text))

    def test_30_shell_changed(self):
        text = replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n        shell: bash {0}\n")
        self.assertRejects("unapproved flag", self.ci(text))

    def test_31_job_level_external_uses(self):
        text = replace_once(BASE, "  verify:\n", "  verify:\n    uses: evil/x/.github/workflows/p.yml@" + SHA + "\n")
        self.assertRejects("local reusable workflow", self.ci(text))

    def test_32_unknown_action_step(self):
        text = BASE + ("  x:\n    runs-on: x\n    steps:\n      - uses: evil/thing@" + SHA + "\n")
        self.assertRejects("unapproved action", self.ci(text))

    def test_33_npm_publish_run(self):
        text = BASE + "  pub:\n    runs-on: x\n    steps:\n      - run: npm publish\n"
        self.assertRejects("unapproved publish route", self.ci(text))

    def test_34_git_push_tags_run(self):
        text = BASE + "  pub:\n    runs-on: x\n    steps:\n      - run: git push origin HEAD:refs/tags/v1\n"
        self.assertRejects("unapproved publish route", self.ci(text))

    def test_35_write_all_permissions(self):
        text = replace_once(BASE, "permissions:\n  contents: read\n", "permissions: write-all\n")
        self.assertRejects("unapproved flag", self.ci(text))

    def test_36_pull_request_target_in_ci(self):
        text = replace_once(BASE, "  pull_request:\n", "  pull_request_target:\n")
        self.assertRejects("triggers changed", self.ci(text))

    def test_37_int_key_collides_with_on(self):
        text = replace_once(BASE, "on:\n  pull_request:\n  push:\n    branches: [main]\n", "on: []\n1:\n  pull_request:\n  push:\n    branches: [main]\n")
        self.assertRejects("non-string key", self.ci(text))

    def test_38_timestamp_job_id(self):
        self.assertRejects("non-string key", self.ci(BASE + "2024-01-01:\n  runs-on: x\n"))

    def test_39_uppercase_workflow_added(self):
        self.assertRejects("added or renamed", {"EXTRA.YML": BASE})

    def test_40_candidate_gate_adds_pull_request(self):
        text = replace_once(GATE, "  pull_request_target:\n", "  pull_request:\n  pull_request_target:\n")
        self.assertRejects("triggers changed", {"gate.yml": text})

    def test_41_candidate_gate_permissions_changed(self):
        text = replace_once(GATE, "permissions:\n  contents: read\n", "permissions: write-all\n")
        self.assertRejects("unapproved flag", {"gate.yml": text})

    def test_42_base_guard_missing(self):
        files = dict(BASE_FILES)
        files["ci.yml"] = replace_once(BASE, "  guard-verify:\n", "  guard-verify-x:\n")
        with self.assertRaises(w.LintError) as ctx:
            w.baseline_from_tree(write_tree(files))
        self.assertIn("base guard-verify job missing", str(ctx.exception))


class Positive(unittest.TestCase):
    def test_control_passes(self):
        self.assertEqual(check(), set())

    def test_17_multiline_run_text_is_not_a_directive(self):
        text = replace_once(BASE, "      - run: echo verify\n", "      - run: |\n          echo verify\n          # if: false\n")
        self.assertEqual(check({"ci.yml": text}), set())

    def test_26_nightly_schedule_only_is_accepted(self):
        self.assertEqual(check(), set())

    def test_27_verify_echo_change_is_accepted(self):
        text = replace_once(BASE, "run: echo verify", "run: echo verify-changed")
        self.assertEqual(check({"ci.yml": text}), set())


if __name__ == "__main__":
    unittest.main()
