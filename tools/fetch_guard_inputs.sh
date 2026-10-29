#!/usr/bin/env bash
# Fetch the read-only data guard_proof.py needs. Usage: fetch_guard_inputs.sh REPO HEAD_SHA OUT_DIR
# Requires GH_TOKEN with checks:read and actions:read. Writes JSON only; nothing is executed from it.
set -eo pipefail
REPO="$1"
HEAD="$2"
OUT="$3"
mkdir -p "$OUT"
gh api "repos/$REPO/commits/$HEAD/check-runs?per_page=100" > "$OUT/cr.json"
gh api "repos/$REPO/actions/runs?head_sha=$HEAD&event=pull_request&per_page=100" > "$OUT/runs.json"
for RID in $(gh api "repos/$REPO/actions/runs?head_sha=$HEAD&event=pull_request&per_page=100" --jq '.workflow_runs[].id'); do
  gh api "repos/$REPO/actions/runs/$RID/jobs?per_page=100" > "$OUT/jobs-$RID.json"
done
