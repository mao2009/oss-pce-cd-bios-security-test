"""Trusted gate entry point. Runs from the base (main) checkout only.

Usage:
  trusted_gate.py CANDIDATE_ROOT BASE_ROOT EVENT_SHA CHECKED_OUT_SHA
      Evaluate the candidate. Prints PASS or FAIL: <reason>. Exit 0 only on PASS.
  trusted_gate.py authorize PR_JSON_FILE EXPECTED_REPO EVAL_SHA EVENT_NAME EVENT_NUMBER
      Decide whether the App may publish. Prints ALLOW or DENY: <reason>.
      Exit 0 only on ALLOW. Use before minting the App token and again before
      posting. Any missing or unexpected field is DENY (fail closed).
  trusted_gate.py publish EVAL_RESULT VERDICT HEAD_SHA CURRENT_HEAD_SHA
      Print the conclusion for the App check run: success or failure.

The baseline is derived from BASE_ROOT at run time. Nothing in CANDIDATE_ROOT
is executed; it is read as data only. The publish and authorize modes do not
import the workflow checker, so they need no third-party dependency.
"""
import json
import re
import sys
from pathlib import Path

SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
MAIN_REF = "main"
PUBLISH_EVENT = "pull_request_target"


def publish_conclusion(eval_result, verdict, head_sha, current_head):
    """Return the check conclusion. Every unexpected input is failure (fail closed)."""
    if eval_result != "success" or verdict != "pass":
        return "failure"
    if not SHA_RE.match(head_sha or ""):
        return "failure"
    if current_head != head_sha:
        return "failure"
    return "success"


def authorize_publish(pr, expected_repo, eval_sha, event_name, event_number):
    """Return (allowed, reason). The PR JSON comes from the GitHub API, read again
    right before publishing. Missing or malformed fields deny."""
    try:
        if event_name != PUBLISH_EVENT:
            return False, "event is not " + PUBLISH_EVENT
        if not expected_repo:
            return False, "expected repository is empty"
        if not re.fullmatch(r"[1-9][0-9]*", str(event_number)) or pr["number"] != int(event_number):
            return False, "PR number does not match the event"
        if pr["base"]["ref"] != MAIN_REF:
            return False, "base ref is not " + MAIN_REF
        if pr["base"]["repo"]["full_name"] != expected_repo:
            return False, "base repository is not " + expected_repo
        if pr["state"] != "open":
            return False, "PR is not open"
        if not SHA_RE.match(eval_sha or ""):
            return False, "evaluated SHA is malformed"
        if pr["head"]["sha"] != eval_sha:
            return False, "PR head moved since evaluation"
    except (KeyError, TypeError):
        return False, "PR data is missing a required field"
    return True, "all publish conditions hold"


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
    if len(sys.argv) == 7 and sys.argv[1] == "authorize":
        pr = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
        allowed, reason = authorize_publish(pr, sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        print(("ALLOW" if allowed else "DENY") + ": " + reason)
        sys.exit(0 if allowed else 1)
    if len(sys.argv) == 6 and sys.argv[1] == "publish":
        print(publish_conclusion(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
        sys.exit(0)
    if len(sys.argv) != 5:
        sys.exit(2)
    result = verdict(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    print(result)
    sys.exit(0 if result == "PASS" else 1)
