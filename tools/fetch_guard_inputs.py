"""Fetch the read-only inputs guard_proof.py needs. Usage: fetch_guard_inputs.py REPO HEAD_SHA OUT_DIR

Requires GH_TOKEN with checks:read, actions:read, contents:read.
- Each listing is read page by page. Every page must report the same total_count,
  the number of items read must equal total_count, and item ids must be unique.
  Any violation (changed listing, duplicates, page cap) fails the whole fetch.
- A file is written with "complete": true only after the last page is verified.
- Each gh call has a timeout and a fixed retry count with fixed backoff, then fails closed.
- Files from an earlier fetch in the same directory are removed first, so a failed
  fetch can never leave a previous run's data for guard_proof to accept.
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
GH_TIMEOUT_SECONDS = 60
KNOWN_FILES = ("cr.json", "runs.json", "ci-contents.json")


class FetchError(Exception):
    pass


def gh_run(args):
    """Run gh and return stdout. Stderr is captured and never printed."""
    try:
        proc = subprocess.run(
            ["gh", "api", *args], capture_output=True, text=True, check=False, timeout=GH_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        raise FetchError("gh timed out after %ds" % GH_TIMEOUT_SECONDS)
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
    """Read and verify every page of a listing. Returns {key, total_count, complete} or raises."""
    items = []
    total = None
    for page in range(1, MAX_PAGES + 1):
        sep = "&" if "?" in path else "?"
        data = gh_json(runner, "%s%sper_page=%d&page=%d" % (path, sep, PAGE, page), sleep=sleep)
        if key not in data or not isinstance(data.get("total_count"), int):
            raise FetchError("listing has no %r key or no total_count" % key)
        if total is None:
            total = data["total_count"]
        elif data["total_count"] != total:
            raise FetchError("listing changed while paging (total_count differs)")
        chunk = data[key]
        items.extend(chunk)
        if len(items) >= total or len(chunk) < PAGE:
            break
    else:
        raise FetchError("listing exceeds %d pages; refusing to guess" % MAX_PAGES)
    if len(items) != total:
        raise FetchError("listing count %d does not match total_count %d" % (len(items), total))
    ids = [item.get("id") for item in items]
    if len(set(ids)) != len(ids):
        raise FetchError("duplicate items while paging (listing changed)")
    return {key: items, "total_count": total, "complete": True}


def clear_stale(out):
    """Remove only files this script writes, so an old fetch cannot leak into a new verdict."""
    for name in KNOWN_FILES:
        (out / name).unlink(missing_ok=True)
    for stale in out.glob("jobs-*.json"):
        stale.unlink()


def fetch(runner, repo, head, out, sleep=time.sleep):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    clear_stale(out)
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
