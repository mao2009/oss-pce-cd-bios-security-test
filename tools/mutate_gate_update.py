"""Mutation harness for gate_update.py. Usage: mutate_gate_update.py REPO_GATE_UPDATE_DIR SCRATCH_PARENT

Each mutation is applied to a fresh directory made by tempfile.mkdtemp (never an existing one).
A mutation must match exactly once, or it is not applied and the run fails. A mutant is killed only
when unittest reports FAIL (assertion) lines for expected tests and no ERROR (import/syntax) lines.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MUTATIONS = [
    ("scope", "if outside:", "if False:", {"test_outside_scope_is_not_an_update"}),
    ("base-sha", 'if approval.get("base_sha") != base_sha_now:', "if False:", {"test_approval_for_other_base_rejected"}),
    ("head-after-approval", 'if approval.get("head_sha") != head_sha:', "if False:", {"test_head_change_after_approval_rejected", "test_old_success_for_old_head_rejected"}),
    ("expiry", "if now - approved_at > APPROVAL_MAX_AGE:", "if False:", {"test_approval_expired_rejected"}),
    ("approver", "if not signers or not all(s in approvers for s in signers):", "if not signers:", {"test_untrusted_approver_rejected"}),
    ("file-hash", "if recorded.get(path) != sha256_hex(files[path]):", "if False:", {"test_checker_tampering_after_approval_rejected"}),
    ("file-cover", "if set(recorded) != set(changed):", "if False:", {"test_approval_not_covering_all_files_rejected"}),
    ("checker", "if not checker(files):", "if False:", {"test_trusted_checker_rejection_propagates"}),
]


def run_mutant(src_dir, scratch, name, old, new, expected):
    tmp = Path(tempfile.mkdtemp(prefix="mut-" + name + "-", dir=scratch))
    (tmp / "tools").mkdir()
    (tmp / "tests").mkdir()
    shutil.copy(Path(src_dir) / "tools" / "gate_update.py", tmp / "tools" / "gate_update.py")
    shutil.copy(Path(src_dir) / "tests" / "test_gate_update.py", tmp / "tests" / "test_gate_update.py")
    target = tmp / "tools" / "gate_update.py"
    text = target.read_text(encoding="utf-8")
    matches = text.count(old)
    if matches != 1:
        return name, "NOT-APPLIED (matches=%d)" % matches, None
    target.write_text(text.replace(old, new), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-I", str(tmp / "tests" / "test_gate_update.py")],
        capture_output=True, text=True, check=False,
    )
    out = proc.stdout + proc.stderr
    failed = {line.split("FAIL: ", 1)[1].split(" ", 1)[0] for line in out.splitlines() if line.startswith("FAIL: ")}
    errored = [line for line in out.splitlines() if line.startswith("ERROR: ")]
    if errored:
        return name, "INVALID (ERROR lines present)", proc.returncode
    if not failed or not failed <= expected:
        return name, "SURVIVED or unexpected failures: " + ",".join(sorted(failed)), proc.returncode
    return name, "KILLED by " + ",".join(sorted(failed)), proc.returncode


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(2)
    src, scratch = sys.argv[1], sys.argv[2]
    bad = 0
    for name, old, new, expected in MUTATIONS:
        result = run_mutant(src, scratch, name, old, new, expected)
        print("%-22s exit=%s %s" % (result[0], result[2], result[1]))
        if not result[1].startswith("KILLED"):
            bad += 1
    print("not-killed=%d of %d" % (bad, len(MUTATIONS)))
    sys.exit(1 if bad else 0)
