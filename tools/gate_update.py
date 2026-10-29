"""Update-only gate. Decides whether a PR that changes the gate itself may publish the gate-update check.

Runs from the base (main) checkout only. The candidate's files are data: they are hashed, never executed.

evaluate() is pure. The caller supplies fresh facts from the API and the trusted approval record:
  pr            PR JSON re-read right before publishing (repo, number, base_ref, state, base_sha, head_sha)
  base_sha_now  main HEAD read from the API now
  changed       PR file listing (complete) as a list of paths
  files         {path: bytes} for each changed path, read from the candidate head
  approval      owner approval record from a source the candidate cannot write, or None
  approvers     trusted approver logins, read from the base checkout
  now           aware datetime

Returns (ok, reason). Anything unproven is False (fail closed).
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

CHECK_NAME = "gate-update"
UPDATE_SCOPE = frozenset({
    ".github/workflows/gate.yml",
    "tools/trusted_gate.py",
    "tools/guard_proof.py",
    "tools/workflow_lint.py",
    "tools/fetch_guard_inputs.py",
    "tools/gate_update.py",
    "tools/requirements-lint.txt",
})
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
APPROVAL_MAX_AGE = timedelta(hours=24)
FUTURE_SKEW = timedelta(minutes=3)


def _aware(value, now):
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed - now > FUTURE_SKEW:
        raise ValueError("timestamp is naive or in the future")
    return parsed


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def evaluate(pr, base_sha_now, changed, files, approval, approvers, checker, now):
    """Return (ok, reason). checker(files) -> bool runs the trusted check on the candidate data."""
    try:
        if pr["base"]["ref"] != "main" or pr["state"] != "open":
            return False, "PR base is not main or PR is not open"
        if not SHA_RE.match(base_sha_now or "") or pr["base"]["sha"] != base_sha_now:
            return False, "PR base SHA is not the current main HEAD"
        head_sha = pr["head"]["sha"]
        if not SHA_RE.match(head_sha or ""):
            return False, "PR head SHA is malformed"
        repo = pr["base"]["repo"]["full_name"]
        number = pr["number"]
    except (KeyError, TypeError):
        return False, "PR data is missing a required field"

    if not changed or len(set(changed)) != len(changed):
        return False, "changed-file listing is empty or contains duplicates"
    outside = sorted(set(changed) - UPDATE_SCOPE)
    if outside:
        return False, "not an update PR: outside update scope: " + ", ".join(outside)
    if set(files) != set(changed):
        return False, "candidate content is missing for a changed file"

    if approval is None:
        return False, "no owner approval record"
    if approval.get("repo") != repo or approval.get("pr") != number:
        return False, "approval is for a different repository or PR"
    if approval.get("base_sha") != base_sha_now:
        return False, "approval is for a different base SHA"
    if approval.get("head_sha") != head_sha:
        return False, "PR head moved after approval"
    try:
        approved_at = _aware(approval.get("approved_at"), now)
    except ValueError as exc:
        return False, "approval time invalid: " + str(exc)
    if now - approved_at > APPROVAL_MAX_AGE:
        return False, "approval expired"
    signers = approval.get("approvers")
    if not signers or not all(s in approvers for s in signers):
        return False, "approval is not from a trusted approver"

    recorded = approval.get("files") or {}
    if set(recorded) != set(changed):
        return False, "approval does not cover exactly the changed files"
    for path in changed:
        if recorded.get(path) != sha256_hex(files[path]):
            return False, "candidate file differs from approved content: " + path

    if not checker(files):
        return False, "trusted checker rejected the update"
    return True, "update approved and checked for head " + head_sha


def publish_conclusion(ok):
    return "success" if ok is True else "failure"


def load_approval(path):
    """Read the approval record from an owner-only directory outside the candidate checkout."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
