"""Fetch the read-only inputs guard_proof.py needs. Usage: fetch_guard_inputs.py REPO HEAD_SHA OUT_DIR

Requires GH_TOKEN with checks:read, actions:read, contents:read.
- Every listing is read page by page. A file is written with "complete": true only
  after the last page; a listing that cannot be finished makes the whole fetch fail.
- Each gh call is retried a fixed number of times with fixed backoff, then fails closed.
- Run ids come from the same runs listing that is written to disk (no second listing).
- Nothing fetched is executed. Stderr and tokens are never printed.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

PAGE = 100
MAX_PAGES = 50
ATTEMPTS = 3
BACKOFF_SECONDS = (2, 4)


class FetchError(Exception):
    pass


def gh_run(args):
    """Run gh and return stdout. The real runner never echoes stderr (it may carry request details)."""
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise FetchError("gh exited %d" % proc.returncode)
    return proc.stdout


def gh_json(runner, path, sleep=time.sleep):
    """One gh call with fixed retries. Any persistent failure raises FetchError."""
    last = None
    for attempt in range(ATTEMPTS):
        try:
            return json.loads(runner([path]))
        except (FetchError, ValueError) as exc:
            last = exc
            if attempt < ATTEMPTS - 1:
                sleep(BACKOFF_SECONDS[attempt])
    raise FetchError("gh api failed after %d attempts: %s" % (ATTEMPTS, last))


def paged(runner, path, key, sleep=time.sleep):
    """Read every page of a listing. Returns {key: [...], "complete": True} or raises."""
    items = []
    for page in range(1, MAX_PAGES + 1):
        sep = "&" if "?" in path else "?"
        data = gh_json(runner, "%s%sper_page=%d&page=%d" % (path, sep, PAGE, page), sleep=sleep)
        if key not in data:
            raise FetchError("listing has no %r key" % key)
        chunk = data[key]
        items.extend(chunk)
        if len(chunk) < PAGE:
            return {key: items, "complete": True}
    raise FetchError("listing exceeds %d pages; refusing to guess" % MAX_PAGES)


def fetch(runner, repo, head, out, sleep=time.sleep):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    cr = paged(runner, "repos/%s/commits/%s/check-runs" % (repo, head), "check_runs", sleep=sleep)
    runs = paged(runner, "repos/%s/actions/runs?head_sha=%s&event=pull_request" % (repo, head), "workflow_runs", sleep=sleep)
    (out / "cr.json").write_text(json.dumps(cr), encoding="utf-8")
    (out / "runs.json").write_text(json.dumps(runs), encoding="utf-8")
    ci = gh_json(runner, "repos/%s/contents/.github/workflows/ci.yml?ref=%s" % (repo, head), sleep=sleep)
    (out / "ci-contents.json").write_text(json.dumps(ci), encoding="utf-8")
    for run in runs["workflow_runs"]:
        jobs = paged(runner, "repos/%s/actions/runs/%d/jobs" % (repo, run["id"]), "jobs", sleep=sleep)
        (out / ("jobs-%d.json" % run["id"])).write_text(json.dumps(jobs), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(2)
    try:
        fetch(gh_run, sys.argv[1], sys.argv[2], sys.argv[3])
    except FetchError as exc:
        print("FAIL: fetch incomplete: " + str(exc))
        sys.exit(1)
