"""Trusted gate entry point. Runs from the base (main) checkout only.

Usage: trusted_gate.py CANDIDATE_ROOT BASE_ROOT EVENT_SHA CHECKED_OUT_SHA

The baseline is derived from BASE_ROOT at run time. Nothing in CANDIDATE_ROOT
is executed; it is read as data only.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import workflow_lint as w  # noqa: E402

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def verdict(candidate_root, base_root, event_sha, checked_out_sha):
    if not SHA_RE.match(event_sha) or event_sha != checked_out_sha:
        return "FAIL: checked-out HEAD does not match PR head"
    try:
        baseline = w.baseline_from_tree(base_root)
        w.check_tree(candidate_root, baseline)
    except w.LintError as exc:
        return "FAIL: " + str(exc)
    return "PASS"


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(2)
    result = verdict(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    print(result)
    sys.exit(0 if result == "PASS" else 1)
