#!/usr/bin/env bash
# Fetch the read-only data guard_proof.py needs. Usage: fetch_guard_inputs.sh REPO HEAD_SHA OUT_DIR
# Requires GH_TOKEN with checks:read, actions:read, contents:read. Writes JSON only; nothing is executed from it.
# The run listing is fetched once, and the run ids are read from that same file (no second listing race).
set -eo pipefail
REPO="$1"
HEAD="$2"
OUT="$3"
mkdir -p "$OUT"
gh api "repos/$REPO/commits/$HEAD/check-runs?per_page=100" > "$OUT/cr.json"
gh api "repos/$REPO/actions/runs?head_sha=$HEAD&event=pull_request&per_page=100" > "$OUT/runs.json"
gh api "repos/$REPO/contents/.github/workflows/ci.yml?ref=$HEAD" > "$OUT/ci-contents.json"
RUN_IDS=$(python3 -c "import json,sys; print(' '.join(str(r['id']) for r in json.load(open(sys.argv[1]))['workflow_runs']))" "$OUT/runs.json")
for RID in $RUN_IDS; do
  gh api "repos/$REPO/actions/runs/$RID/jobs?per_page=100" > "$OUT/jobs-$RID.json"
done
