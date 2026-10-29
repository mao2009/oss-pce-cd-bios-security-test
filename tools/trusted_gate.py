"""Trusted gate entry point. Runs from the base (main) checkout only.

Usage:
  trusted_gate.py CANDIDATE_ROOT BASE_ROOT EVENT_SHA CHECKED_OUT_SHA
      Evaluate the candidate. Prints PASS or FAIL: <reason>. Exit 0 only on PASS.
  trusted_gate.py publish EVAL_RESULT VERDICT HEAD_SHA CURRENT_HEAD_SHA
      Print the conclusion for the App check run: success or failure.

The baseline is derived from BASE_ROOT at run time. Nothing in CANDIDATE_ROOT
is executed; it is read as data only. The publish mode does not import the
workflow checker, so it needs no third-party dependency.
"""
import re
import sys
from pathlib import Path

SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


def publish_conclusion(eval_result, verdict, head_sha, current_head):
    """Return the check conclusion. Every unexpected input is failure (fail closed)."""
    if eval_result != "success" or verdict != "pass":
        return "failure"
    if not SHA_RE.match(head_sha or ""):
        return "failure"
    if current_head != head_sha:
        return "failure"
    return "success"


def verdict(candidate_root, base_root, event_sha, checked_out_sha):
    if not SHA_RE.match(event_sha or "") or event_sha != checked_out_sha:
        return "FAIL: checked-out HEAD does not match PR head"
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import workflow_lint as w  # noqa: E402  (needs PyYAML; missing module must fail the gate)

    try:
        baseline = w.baseline_from_tree(base_root)
        w.check_tree(candidate_root, baseline)
    except w.LintError as exc:
        return "FAIL: " + str(exc)
    return "PASS"


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "publish":
        print(publish_conclusion(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
        sys.exit(0)
    if len(sys.argv) != 5:
        sys.exit(2)
    result = verdict(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    print(result)
    sys.exit(0 if result == "PASS" else 1)
