"""Strict workflow checks for the trusted gate (A3).

Rejects YAML that PyYAML would silently accept but GitHub Actions may read
differently: duplicate keys, anchors, aliases, merge keys, directives, BOM,
ambiguous bool keys, and unknown tags. Structural checks then cover the
trigger, disabled jobs, publish routes, and the guard job's canonical form.
"""
import hashlib
import json
import re
from pathlib import Path

import yaml
from yaml.events import AliasEvent

BOOL_TAG = "tag:yaml.org,2002:bool"
MERGE_TAG = "tag:yaml.org,2002:merge"
GUARD_JOB = "guard-verify"
PUBLISH_USES = re.compile(
    r"^(actions/(upload-artifact|upload-pages-artifact|deploy-pages|attest)|softprops/|ncipollo/)",
    re.IGNORECASE,
)
PUBLISH_RUN = re.compile(r"gh\s+release|gh\s+api[^\n]*uploads|curl[^\n]*upload", re.IGNORECASE)
SHA_PIN = re.compile(r"@[0-9a-f]{40}$")


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
                    continue
                key = key_node.value
                if key_node.tag == MERGE_TAG or key == "<<":
                    raise LintError("merge key is not allowed")
                if key in seen:
                    raise LintError("duplicate key: " + repr(key))
                seen.add(key)
                if key_node.tag == BOOL_TAG and key != "on":
                    raise LintError("ambiguous bool key: " + repr(key))
        return super().construct_mapping(node, deep)


def parse_workflow(text):
    if text.startswith("\ufeff"):
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
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _is_constant_false(value):
    return value is False or (isinstance(value, str) and value.strip().strip("${} ").lower() == "false")


def trigger_names(doc):
    triggers = doc.get("on")
    if isinstance(triggers, dict):
        return set(triggers)
    if isinstance(triggers, list):
        return set(triggers)
    if isinstance(triggers, str):
        return {triggers}
    return set()


def check_workflow(name, doc):
    if not trigger_names(doc):
        raise LintError(name + ": trigger (on) missing or disabled")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        raise LintError(name + ": jobs missing")
    publish = set()
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            raise LintError(name + ": job " + job_id + " is not a mapping")
        if _is_constant_false(job.get("if")):
            raise LintError(name + ": job " + job_id + " disabled by if")
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses", ""))
            if uses:
                if uses.startswith("./") or ".github/workflows/" in uses:
                    raise LintError(name + ": local action/reusable workflow " + uses)
                if PUBLISH_USES.match(uses):
                    publish.add(name + ":" + job_id)
                if not SHA_PIN.search(uses):
                    raise LintError(name + ": unpinned action " + uses)
            if PUBLISH_RUN.search(str(step.get("run", ""))):
                publish.add(name + ":" + job_id)
    return publish


def check_tree(root, baseline):
    """Compare the candidate tree against a trusted baseline.

    `baseline` must come from the trusted base branch, never from the
    candidate tree. Returns the set of publish routes found.
    """
    root = Path(root)
    wf_dir = root / ".github" / "workflows"
    if (root / ".github" / "actions").exists():
        raise LintError("local composite actions are not allowed")
    expected_files = baseline["files"]
    present = {p.name for p in wf_dir.glob("*.y*ml")}
    removed = set(expected_files) - present
    if removed:
        raise LintError("workflow removed or renamed: " + ", ".join(sorted(removed)))
    added = present - set(expected_files)
    if added:
        raise LintError("workflow added or renamed: " + ", ".join(sorted(added)))
    publish = set()
    for name in sorted(present):
        doc = parse_workflow((wf_dir / name).read_text(encoding="utf-8"))
        if trigger_names(doc) != set(expected_files[name]["triggers"]):
            raise LintError(name + ": triggers changed")
        publish |= check_workflow(name, doc)
        if name == "ci.yml":
            guard = doc["jobs"].get(GUARD_JOB)
            if guard is None:
                raise LintError("guard-verify job missing")
            if canonical_digest(guard) != baseline["guard_digest"]:
                raise LintError("guard-verify job changed")
    unexpected = publish - set(baseline["publish"])
    if unexpected:
        raise LintError("unapproved publish route: " + ", ".join(sorted(unexpected)))
    missing = set(baseline["publish"]) - publish
    if missing:
        raise LintError("baseline publish route removed: " + ", ".join(sorted(missing)))
    return publish