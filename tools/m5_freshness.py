"""M5 freshness: a success is published only for one PR head, one main, one run, one policy.

A check the gate posts must be backed by an evaluation made by this run, for the
PR head and main that are still current when the check is posted. The API is
injected: any object with get_pr(repo, number), get_ref(repo, ref) and
post_check(repo, head, conclusion). The real App-backed client needs a separate
App and credential (not created here); tests use a fake.

Every API failure, timeout, or malformed field denies (fail closed).
"""
import re
from datetime import datetime, timedelta

POLICY_VERSION = "m5-1"
MAIN_REF = "heads/main"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
MAX_EVAL_AGE = timedelta(minutes=30)
FUTURE_SKEW = timedelta(minutes=3)


def _parse_time(value):
    if not isinstance(value, str):
        raise ValueError("time is not a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("time has no timezone")
    return parsed


def context_problem(ctx):
    """The evaluation context: repo, PR number, PR head, main base, policy. None means valid."""
    if not isinstance(ctx, dict):
        return "context is not a mapping"
    if ctx.get("policy") != POLICY_VERSION:
        return "policy version is not the trusted one"
    if not isinstance(ctx.get("repo"), str) or not REPO_RE.match(ctx["repo"]):
        return "repository is malformed"
    number = ctx.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        return "PR number is malformed"
    for key in ("head", "base"):
        if not isinstance(ctx.get(key), str) or not SHA_RE.match(ctx[key]):
            return key + " SHA is malformed"
    return None


def live_problem(api, ctx):
    """Re-read the PR and main from the API. None means both are still current."""
    try:
        pr = api.get_pr(ctx["repo"], ctx["number"])
        main = api.get_ref(ctx["repo"], MAIN_REF)
    except Exception as exc:  # any API failure, timeout included, fails closed
        return "API error: " + type(exc).__name__
    try:
        if pr["number"] != ctx["number"]:
            return "PR number mismatch"
        if pr["state"] != "open":
            return "PR is not open"
        if pr["base"]["ref"] != "main":
            return "base ref is not main"
        if pr["base"]["repo"]["full_name"] != ctx["repo"]:
            return "base repository mismatch"
        if pr["head"]["sha"] != ctx["head"]:
            return "PR head moved since evaluation"
    except (KeyError, TypeError):
        return "PR data is missing a required field"
    if not isinstance(main, str) or not SHA_RE.match(main):
        return "main SHA is malformed"
    if main != ctx["base"]:
        return "main moved since the evaluation base"
    return None


def record_problem(record, ctx, run_id, now):
    """The evaluation record must come from this run, this context, and a recent time."""
    if not isinstance(record, dict):
        return "evaluation record is not a mapping"
    if record.get("run_id") != run_id:
        return "evaluation is from another workflow run"
    if record.get("repo") != ctx["repo"] or record.get("number") != ctx["number"]:
        return "evaluation is for another PR"
    if record.get("head") != ctx["head"]:
        return "evaluation is for another head"
    if record.get("base") != ctx["base"]:
        return "evaluation used another base"
    if record.get("policy") != ctx["policy"]:
        return "evaluation policy version mismatch"
    try:
        at = _parse_time(record.get("evaluated_at"))
    except ValueError:
        return "evaluation time is invalid"
    if at - now > FUTURE_SKEW:
        return "evaluation time is in the future"
    if now - at > MAX_EVAL_AGE:
        return "evaluation is stale"
    return None


def begin_evaluation(api, ctx):
    """Check before evaluating. Returns a reason to stop, or None."""
    return context_problem(ctx) or live_problem(api, ctx)


def post_verdict(api, ctx, record, run_id, now, conclusion):
    """Re-check right before posting. Returns (posted, reason). Nothing is posted on any doubt."""
    if conclusion not in ("success", "failure"):
        return False, "conclusion is malformed"
    reason = context_problem(ctx) or record_problem(record, ctx, run_id, now) or live_problem(api, ctx)
    if reason is None and conclusion == "success" and record.get("verdict") != "PASS":
        reason = "a success needs a PASS verdict"
    if reason is not None:
        return False, reason
    api.post_check(ctx["repo"], ctx["head"], conclusion)
    return True, "posted " + conclusion
