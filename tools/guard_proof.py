"""Trusted proof that the canonical guard-verify job succeeded on this head.

Inputs are JSON files fetched by the gate (read-only GITHUB_TOKEN):
  cr.json              check-runs for the head commit
  runs.json            workflow runs for the head commit with event=pull_request
  jobs-<run_id>.json   jobs of each candidate run
  ci-contents.json     the candidate's .github/workflows/ci.yml at the head (base64, from the contents API)

The verdict is one of PASS, PENDING, or FAIL: <reason>. Anything not positively
proven is FAIL (or PENDING while the job may still be running, which the caller
must bound with a deadline and turn into FAIL). Nothing in these files is
executed; they are read as data.

The proof does not rely on the evaluate verdict. It re-checks the candidate's
own guard job against the trusted base digest, so a forged guard-verify job in
the candidate's ci.yml is rejected here as well.
"""
import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import workflow_lint as w  # noqa: E402  (PyYAML; a missing module must fail the proof)

GUARD_JOB = "guard-verify"
CI_PATH = ".github/workflows/ci.yml"
GITHUB_ACTIONS_APP_ID = 15368
MAX_AGE = timedelta(hours=24)
PAGE_LIMIT = 100


def _ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def candidate_guard_digest(directory):
    """Digest of the candidate's guard job, parsed strictly from the contents API data."""
    raw = _load(Path(directory) / "ci-contents.json")
    text = base64.b64decode(raw["content"]).decode("utf-8")
    doc = w.parse_workflow(text)
    job = doc.get("jobs", {}).get(GUARD_JOB)
    if job is None:
        return None
    return w.canonical_digest(job)


def verify_guard(directory, repo, pr_number, head_sha, base_required_steps, base_guard_digest, now):
    """Return (verdict, proof). proof holds run/job/check ids for the audit log."""
    d = Path(directory)
    try:
        cr = _load(d / "cr.json")
        runs = _load(d / "runs.json")
    except (OSError, ValueError) as exc:
        return "FAIL: check or run data unreadable (" + type(exc).__name__ + ")", None

    check_runs = cr.get("check_runs", [])
    workflow_runs = runs.get("workflow_runs", [])
    if len(check_runs) >= PAGE_LIMIT or len(workflow_runs) >= PAGE_LIMIT:
        return "FAIL: listing may be truncated at the page limit", None

    try:
        candidate_digest = candidate_guard_digest(d)
    except (OSError, ValueError, KeyError, w.LintError) as exc:
        return "FAIL: candidate ci.yml unreadable or invalid: " + str(exc), None
    if candidate_digest is None or candidate_digest != base_guard_digest:
        return "FAIL: candidate guard-verify job differs from the trusted base", None

    checks = [c for c in check_runs if c.get("name") == GUARD_JOB]
    if not checks:
        return "PENDING: guard-verify check not present yet", None
    # Only checks issued by GitHub Actions count. A same-named check from another app is ignored.
    trusted = [c for c in checks if (c.get("app") or {}).get("id") == GITHUB_ACTIONS_APP_ID]
    if not trusted:
        return "FAIL: guard-verify exists only from an untrusted app", None
    check = max(trusted, key=lambda c: c.get("completed_at") or "")
    if check.get("head_sha") != head_sha:
        return "FAIL: guard-verify check is for a different head", None
    if check.get("status") != "completed":
        return "PENDING: guard-verify still running", None
    if check.get("conclusion") != "success":
        return "FAIL: guard-verify conclusion is " + str(check.get("conclusion")), None
    completed = check.get("completed_at")
    if not completed:
        return "FAIL: guard-verify has no completion time", None
    if now - _ts(completed) > MAX_AGE:
        return "FAIL: guard-verify result is expired", None

    # The check's html_url names the run and job: https://github.com/<repo>/actions/runs/<run>/job/<job>
    url = check.get("html_url") or ""
    marker = "/" + repo + "/actions/runs/"
    if marker not in url or "/job/" not in url:
        return "FAIL: guard-verify check has no run reference", None
    try:
        run_id = int(url.split(marker, 1)[1].split("/", 1)[0])
        job_id = int(url.rsplit("/job/", 1)[1].split("?", 1)[0].split("/", 1)[0])
    except (ValueError, IndexError):
        return "FAIL: guard-verify run reference is malformed", None

    run = next((r for r in workflow_runs if r.get("id") == run_id), None)
    if run is None:
        return "FAIL: guard-verify run is not among the head's pull_request runs", None
    if run.get("head_sha") != head_sha:
        return "FAIL: run head does not match the PR head", None
    if run.get("event") != "pull_request":
        return "FAIL: guard-verify ran under event " + str(run.get("event")), None
    if run.get("path") != CI_PATH:
        return "FAIL: guard-verify ran from " + str(run.get("path")), None
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return "FAIL: run is " + str(run.get("status")) + "/" + str(run.get("conclusion")), None
    if pr_number not in [p.get("number") for p in run.get("pull_requests", [])]:
        return "FAIL: run is not associated with this PR", None

    try:
        jobs = _load(d / ("jobs-%d.json" % run_id)).get("jobs", [])
    except (OSError, ValueError):
        return "FAIL: job data for the run is unreadable", None
    if len(jobs) >= PAGE_LIMIT:
        return "FAIL: job listing may be truncated at the page limit", None
    # Display names are not unique in a workflow. Two jobs named guard-verify (for example a
    # candidate job with `name: guard-verify`) make the identity ambiguous, so it fails closed.
    named = [j for j in jobs if j.get("name") == GUARD_JOB]
    if len(named) != 1:
        return "FAIL: expected exactly one guard-verify job in the run, found " + str(len(named)), None
    job = next((j for j in named if j.get("id") == job_id), None)
    if job is None:
        return "FAIL: guard-verify job not found in the run", None
    if job.get("head_sha") != head_sha:
        return "FAIL: job head does not match", None
    if job.get("status") != "completed" or job.get("conclusion") != "success":
        return "FAIL: guard-verify job is " + str(job.get("status")) + "/" + str(job.get("conclusion")), None
    steps = {s.get("name"): s.get("conclusion") for s in job.get("steps", [])}
    for name in base_required_steps:
        if steps.get(name) != "success":
            return "FAIL: required guard step did not succeed: " + name, None

    proof = {"run_id": run_id, "job_id": job_id, "check_run_id": check.get("id"), "head_sha": head_sha}
    return "PASS", proof


def required_steps_from_base(base_guard_job):
    """Named steps of the trusted base's guard job. Their success is required."""
    return [s["name"] for s in base_guard_job.get("steps", []) if "name" in s]


if __name__ == "__main__":
    from datetime import datetime as _dt

    # Usage: guard_proof.py DIR REPO PR_NUMBER HEAD_SHA BASE_ROOT
    # Required steps and the guard digest come from the trusted base checkout only.
    if len(sys.argv) != 6:
        sys.exit(2)
    directory, repo, pr_number, head_sha, base_root = sys.argv[1:6]
    base_ci = w.parse_workflow((Path(base_root) / ".github" / "workflows" / "ci.yml").read_bytes().decode("utf-8"))
    base_job = base_ci["jobs"][GUARD_JOB]
    verdict, proof = verify_guard(
        directory, repo, int(pr_number), head_sha, required_steps_from_base(base_job),
        w.canonical_digest(base_job), _dt.now(timezone.utc),
    )
    print(verdict if proof is None else "PASS " + json.dumps(proof, sort_keys=True))
    sys.exit(0 if verdict.startswith("PASS") else (3 if verdict.startswith("PENDING") else 1))
