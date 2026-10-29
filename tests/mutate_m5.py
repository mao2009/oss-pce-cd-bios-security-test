"""Mutation check for tools/m5_freshness.py.

Each mutant is one textual edit applied to a fresh copy in a new temporary directory.
The target text must occur exactly once, or the mutant is not applied. A mutant counts
as detected only when the M5 tests report at least one failure and no errors: an error
is an import or syntax problem, not a security test. Run from the repository root.
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()
SOURCE = ROOT / "tools" / "m5_freshness.py"

MUTANTS = [
    ("main-check-removed", 'if main != ctx["base"]:', "if False:"),
    ("head-check-removed", 'if pr["head"]["sha"] != ctx["head"]:', "if False:"),
    ("run-id-check-removed", 'if record.get("run_id") != run_id:', "if False:"),
    ("record-policy-check-removed", 'if record.get("policy") != ctx["policy"]:', "if False:"),
    ("api-error-allowed", 'return "API error: " + type(exc).__name__', "return None"),
    ("staleness-check-removed", "if now - at > MAX_EVAL_AGE:", "if False:"),
    ("post-recheck-removed", "if reason is not None:\n        return False, reason", "if False:\n        return False, reason"),
    ("pass-verdict-check-removed", 'and record.get("verdict") != "PASS":', "and False:"),
]

SUMMARY = re.compile(r"Ran (\d+) tests?")
FAILURES = re.compile(r"failures=(\d+)")
ERRORS = re.compile(r"errors=(\d+)")


def run_mutant(name, old, new, source, scratch):
    count = source.count(old)
    if count != 1:
        return name, "NOT_APPLIED (match count %d)" % count, False
    work = Path(tempfile.mkdtemp(prefix="m5-" + name + "-", dir=scratch))
    shutil.copytree(ROOT / "tools", work / "tools")
    shutil.copytree(ROOT / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    (work / "tools" / "m5_freshness.py").write_text(source.replace(old, new, 1), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_m5_*.py"],
        cwd=work, capture_output=True, text=True,
    )
    text = proc.stderr
    failures = FAILURES.findall(text)
    errors = ERRORS.findall(text)
    failed = int(failures[-1]) if failures else 0
    errored = int(errors[-1]) if errors else 0
    detected = failed >= 1 and errored == 0
    status = "DETECTED failures=%d errors=%d exit=%d" % (failed, errored, proc.returncode)
    return name, status, detected


def main():
    source = SOURCE.read_text(encoding="utf-8")
    scratch = Path(tempfile.mkdtemp(prefix="m5-mutants-"))
    results = [run_mutant(*mutant, source, scratch) for mutant in MUTANTS]
    for name, status, _ in results:
        print("%-30s %s" % (name, status))
    print("scratch: " + str(scratch))
    return 0 if all(detected for _, _, detected in results) else 1


if __name__ == "__main__":
    sys.exit(main())
