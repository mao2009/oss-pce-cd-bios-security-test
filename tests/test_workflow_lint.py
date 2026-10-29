import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "tools")
import workflow_lint as w  # noqa: E402

BASE = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
SHA = "11d5960a326750d5838078e36cf38b85af677262"


def run(ci_text, extra=None):
    root = Path(tempfile.mkdtemp())
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(ci_text, encoding="utf-8")
    for rel, text in (extra or {}).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return w.check_tree(root)


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


class NegativeCases(unittest.TestCase):
    def assertRejects(self, text, needle=None, extra=None):
        with self.assertRaises(w.LintError) as ctx:
            run(text, extra)
        if needle:
            self.assertIn(needle, str(ctx.exception))

    def test_01_duplicate_on(self):
        self.assertRejects("on: push\n" + BASE, "duplicate key: 'on'")

    def test_02_duplicate_jobs(self):
        self.assertRejects(BASE + "jobs:\n  x:\n    runs-on: x\n", "duplicate key: 'jobs'")

    def test_03_duplicate_steps(self):
        text = replace_once(BASE, "    needs: verify\n", "    needs: verify\n    steps:\n      - run: echo x\n")
        self.assertRejects(text, "duplicate key: 'steps'")

    def test_04_duplicate_run(self):
        text = replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n        run: echo two\n")
        self.assertRejects(text, "duplicate key: 'run'")

    def test_05_on_disabled(self):
        text = replace_once(BASE, "on:\n  pull_request:\n  push:\n    branches: [main]\n", "on: []\n")
        self.assertRejects(text, "trigger")

    def test_06_guard_if_false(self):
        text = replace_once(BASE, "  guard-verify:\n", "  guard-verify:\n    if: false\n")
        self.assertRejects(text, "disabled by if")

    def test_07_guard_renamed(self):
        text = replace_once(BASE, "  guard-verify:\n", "  guard-verify-x:\n")
        self.assertRejects(text, "guard-verify job missing")

    def test_08_pull_request_trigger_removed(self):
        text = replace_once(BASE, "  pull_request:\n", "")
        self.assertRejects(text, "no pull_request trigger")

    def test_09_merge_key(self):
        text = replace_once(BASE, "  verify:\n", "  verify:\n    <<: {runs-on: x}\n")
        self.assertRejects(text, "merge key")

    def test_10_anchor_alias(self):
        text = replace_once(BASE, "    runs-on: ubuntu-24.04\n    steps:\n      - run: echo verify", "    runs-on: &r ubuntu-24.04\n    steps:\n      - run: echo verify")
        self.assertRejects(text, "anchor")

    def test_11_guard_shell_changed(self):
        text = replace_once(BASE, "  guard-verify:\n", "  guard-verify:\n    defaults:\n      run:\n        shell: sh\n")
        self.assertRejects(text, "guard-verify job changed")

    def test_12_guard_checkout_ref_changed(self):
        text = replace_once(BASE, "      - run: echo guard\n", "      - uses: actions/checkout@" + SHA + "\n        with:\n          ref: main\n")
        self.assertRejects(text, "guard-verify job changed")

    def test_13_guard_uses_replaced(self):
        text = replace_once(BASE, "      - run: echo guard\n", "      - uses: actions/checkout@" + SHA + "\n")
        self.assertRejects(text, "guard-verify job changed")

    def test_14_new_publish_job(self):
        text = BASE + ("  publish:\n    runs-on: x\n    steps:\n      - uses: actions/upload-artifact@" + SHA + "\n        with:\n          name: x\n          path: x\n")
        self.assertRejects(text, "unapproved publish route")

    def test_15_composite_action_publish(self):
        action = "name: x\nruns:\n  using: composite\n  steps:\n    - uses: actions/upload-artifact@" + SHA + "\n      with:\n        name: x\n        path: x\n"
        text = BASE + "  pub:\n    runs-on: x\n    steps:\n      - uses: ./.github/actions/x\n"
        self.assertRejects(text, None, extra={".github/actions/x/action.yml": action})

    def test_16_gh_release_in_run(self):
        text = BASE + "  rel:\n    runs-on: x\n    steps:\n      - run: gh release create v1 x\n"
        self.assertRejects(text, "unapproved publish route")


    def test_18_ambiguous_bool_key(self):
        text = replace_once(BASE, "  verify:\n", "  verify:\n    yes:\n      x: 1\n")
        self.assertRejects(text, "ambiguous bool key")
class FalsePositive(unittest.TestCase):
    def test_17_multiline_run_text_is_not_a_directive(self):
        text = replace_once(BASE, "      - run: echo verify\n", "      - run: |\n          echo verify\n          # if: false\n")
        publish = run(text)
        self.assertEqual(publish, set())


if __name__ == "__main__":
    unittest.main()
