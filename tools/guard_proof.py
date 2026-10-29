"""Trusted proof that the canonical guard-verify job succeeded on this head.

Inputs are JSON files fetched by the gate (read-only GITHUB_TOKEN):
  cr.json              check-runs for the head commit
  runs.json            workflow runs for the head commit with event=pull_request
  jobs-<run_id>.json   jobs of each candidate run

The verdict is one of PASS, PENDING, or FAIL: <reason>. Anything not positively
proven is FAIL (or PENDING while the job may still be running, which the caller
must bound with a deadline and turn into FAIL). Nothing in these files is
executed; they are read as data.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

GUARD_JOB = "guard-verify"
CI_PATH = ".github/workflows/ci.yml"
GITHUB_ACTIONS_APP_ID = 15368
MAX_AGE = timedelta(hours=24)


def _ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_guard(directory, repo, pr_number, head_sha, base_required_steps, now):
    """Return (verdict, proof). proof holds run/job/check ids for the audit log."""
    d = Path(directory)
    try:
        cr = _load(d / "cr.json")
        runs = _load(d / "runs.json")
    except (OSError, ValueError) as exc:
        return "FAIL: check or run data unreadable (" + type(exc).__name__ + ")", None

    checks = [c for c in cr.get("check_runs", []) if c.get("name") == GUARD_JOB]
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

    run = next((r for r in runs.get("workflow_runs", []) if r.get("id") == run_id), None)
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
    job = next((j for j in jobs if j.get("id") == job_id and j.get("name") == GUARD_JOB), None)
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
    import sys

    # Usage: guard_proof.py DIR REPO PR_NUMBER HEAD_SHA BASE_ROOT
    # Required steps come from the trusted base checkout, never from the candidate.
    if len(sys.argv) != 6:
        sys.exit(2)
    directory, repo, pr_number, head_sha, base_root = sys.argv[1:6]
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import workflow_lint as w  # noqa: E402

    base_ci = w.parse_workflow((Path(base_root) / ".github" / "workflows" / "ci.yml").read_bytes().decode("utf-8"))
    required = required_steps_from_base(base_ci["jobs"][GUARD_JOB])
    verdict, proof = verify_guard(directory, repo, int(pr_number), head_sha, required, datetime.now(timezone.utc))
    print(verdict if proof is None else "PASS " + json.dumps(proof, sort_keys=True))
    sys.exit(0 if verdict.startswith("PASS") else (3 if verdict.startswith("PENDING") else 1))
