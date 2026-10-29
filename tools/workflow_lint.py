"""Strict workflow checks for the trusted gate (A3, v3).

The trusted baseline is derived from the BASE tree (main) at run time, never
from the candidate tree. Every candidate workflow is compared to it with
default-deny rules: triggers, job/step flags (if, continue-on-error, shell,
permissions, job-level uses and secrets), third-party action references, and
publish routes must match the base exactly. The guard-verify job is compared
by canonical digest taken from the base tree.

Known residual gap: publish routes in `run:` text are a denylist (PUBLISH_RUN).
Only action references and flags are default-deny.
"""
import hashlib
import json
import re
from pathlib import Path

import yaml
from yaml.events import AliasEvent

STR_TAG = "tag:yaml.org,2002:str"
BOOL_TAG = "tag:yaml.org,2002:bool"
MERGE_TAG = "tag:yaml.org,2002:merge"
GUARD_JOB = "guard-verify"
CI_FILE = "ci.yml"
PUBLISH_USES = re.compile(
    r"^(actions/(upload-artifact|upload-pages-artifact|deploy-pages|attest)|softprops/|ncipollo/|peter-evans/|actions/github-script)",
    re.IGNORECASE,
)
PUBLISH_RUN = re.compile(
    r"gh\s+release|gh\s+api[^\n]*upload|curl[^\n]*upload|npm\s+publish|twine\s+upload|docker\s+push|cargo\s+publish|git\s+push[^\n]*(tags|refs)",
    re.IGNORECASE,
)
SHA_PIN = re.compile(r"@[0-9a-f]{40}$")
STEP_FLAG_KEYS = ("if", "continue-on-error", "shell")
JOB_FLAG_KEYS = ("if", "permissions", "secrets", "uses")


class LintError(Exception):
    pass


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise LintError("alias (anchor reference) is not allowed")
        event = self.peek_event()
        if getattr(event, "anchor", None):
            raise LintError("anchor is not allowed")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for key_node, _ in node.value:
                if not isinstance(key_node, yaml.ScalarNode):
                    raise LintError("non-scalar key is not allowed")
                key = key_node.value
                if key_node.tag == MERGE_TAG or key == "<<":
                    raise LintError("merge key is not allowed")
                if key in seen:
                    raise LintError("duplicate key: " + repr(key))
                seen.add(key)
                if key_node.tag == BOOL_TAG:
                    if key != "on":
                        raise LintError("ambiguous bool key: " + repr(key))
                elif key_node.tag != STR_TAG:
                    raise LintError("non-string key: " + repr(key))
        return super().construct_mapping(node, deep)


def parse_workflow(text):
    if text.startswith("﻿"):
        raise LintError("BOM is not allowed")
    for line in text.splitlines():
        if line.startswith("%"):
            raise LintError("directive is not allowed")
    try:
        doc = yaml.load(text, Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise LintError("yaml error: " + str(exc).splitlines()[0])
    if not isinstance(doc, dict):
        raise LintError("workflow must be a mapping")
    if True in doc:
        # YAML 1.1 reads a bare `on` as bool; GitHub reads it as the trigger key.
        doc["on"] = doc.pop(True)
    return doc


def canonical_digest(obj):
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def trigger_names(doc):
    triggers = doc.get("on")
    if isinstance(triggers, dict):
        return set(triggers)
    if isinstance(triggers, list):
        return set(triggers)
    if isinstance(triggers, str):
        return {triggers}
    return set()


def _flag(name, job, step, key, value):
    return "|".join([name, job, step, key, json.dumps(value, sort_keys=True, default=str)])


def scan_workflow(name, doc):
    """Return (publish routes, flags, action references) for one workflow."""
    if not trigger_names(doc):
        raise LintError(name + ": trigger (on) missing or disabled")
    flags = set()
    publish = set()
    uses_seen = set()
    if "permissions" in doc:
        flags.add(_flag(name, "-", "-", "permissions", doc["permissions"]))
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        raise LintError(name + ": jobs missing")
    for job_id, job in jobs.items():
        if not isinstance(job_id, str):
            raise LintError(name + ": job id is not a string")
        if not isinstance(job, dict):
            raise LintError(name + ": job " + job_id + " is not a mapping")
        for key in JOB_FLAG_KEYS:
            if key in job:
                flags.add(_flag(name, job_id, "-", key, job[key]))
        job_uses = str(job.get("uses", ""))
        if job_uses and (job_uses.startswith("./") or ".github/workflows/" in job_uses):
            raise LintError(name + ": local reusable workflow " + job_uses)
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            raise LintError(name + ": job " + job_id + " steps is not a list")
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise LintError(name + ": step is not a mapping")
            for key in STEP_FLAG_KEYS:
                if key in step:
                    flags.add(_flag(name, job_id, str(index), key, step[key]))
            uses = str(step.get("uses", ""))
            if uses:
                if uses.startswith("./") or ".github/workflows/" in uses:
                    raise LintError(name + ": local action " + uses)
                if not SHA_PIN.search(uses):
                    raise LintError(name + ": unpinned action " + uses)
                uses_seen.add(uses)
                if PUBLISH_USES.match(uses):
                    publish.add(name + ":" + job_id)
            if PUBLISH_RUN.search(str(step.get("run", ""))):
                publish.add(name + ":" + job_id)
    return publish, flags, uses_seen


def workflow_files(root):
    wf = Path(root) / ".github" / "workflows"
    if not wf.is_dir():
        return {}
    return {
        p.name: p.read_text(encoding="utf-8")
        for p in sorted(wf.iterdir())
        if p.is_file() and p.name.lower().endswith((".yml", ".yaml"))
    }


def baseline_from_tree(root):
    """Build the trusted baseline from the base tree (main)."""
    texts = workflow_files(root)
    if CI_FILE not in texts:
        raise LintError("base ci.yml missing")
    baseline = {"files": {}, "publish": set(), "flags": set(), "actions": set()}
    for name, text in texts.items():
        doc = parse_workflow(text)
        publish, flags, uses = scan_workflow(name, doc)
        baseline["files"][name] = {"triggers": sorted(trigger_names(doc))}
        baseline["publish"] |= publish
        baseline["flags"] |= flags
        baseline["actions"] |= uses
        if name == CI_FILE:
            guard = doc.get("jobs", {}).get(GUARD_JOB)
            if guard is None:
                raise LintError("base guard-verify job missing")
            baseline["guard_digest"] = canonical_digest(guard)
    return {
        "files": baseline["files"],
        "publish": sorted(baseline["publish"]),
        "flags": sorted(baseline["flags"]),
        "actions": sorted(baseline["actions"]),
        "guard_digest": baseline["guard_digest"],
    }


def check_tree(root, baseline):
    """Compare a candidate tree with the trusted baseline. Return publish routes."""
    root = Path(root)
    if (root / ".github" / "actions").exists():
        raise LintError("local composite actions are not allowed")
    texts = workflow_files(root)
    expected = baseline["files"]
    removed = set(expected) - set(texts)
    if removed:
        raise LintError("workflow removed or renamed: " + ", ".join(sorted(removed)))
    added = set(texts) - set(expected)
    if added:
        raise LintError("workflow added or renamed: " + ", ".join(sorted(added)))
    publish = set()
    flags = set()
    uses = set()
    for name in sorted(texts):
        doc = parse_workflow(texts[name])
        if trigger_names(doc) != set(expected[name]["triggers"]):
            raise LintError(name + ": triggers changed")
        p, f, u = scan_workflow(name, doc)
        publish |= p
        flags |= f
        uses |= u
        if name == CI_FILE:
            guard = doc["jobs"].get(GUARD_JOB)
            if guard is None:
                raise LintError("guard-verify job missing")
            if canonical_digest(guard) != baseline["guard_digest"]:
                raise LintError("guard-verify job changed")
    unknown_uses = uses - set(baseline["actions"])
    if unknown_uses:
        raise LintError("unapproved action: " + ", ".join(sorted(unknown_uses)))
    unexpected_flags = flags - set(baseline["flags"])
    if unexpected_flags:
        raise LintError("unapproved flag: " + " ; ".join(sorted(unexpected_flags)))
    missing_flags = set(baseline["flags"]) - flags
    if missing_flags:
        raise LintError("baseline flag removed: " + " ; ".join(sorted(missing_flags)))
    unexpected = publish - set(baseline["publish"])
    if unexpected:
        raise LintError("unapproved publish route: " + ", ".join(sorted(unexpected)))
    missing = set(baseline["publish"]) - publish
    if missing:
        raise LintError("baseline publish route removed: " + ", ".join(sorted(missing)))
    return publish
