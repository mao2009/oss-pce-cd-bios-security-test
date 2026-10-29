"""Real guard-verify check (replaces the echo stub). Runs the vendored production artifact guard on a candidate tree.

Usage: guard_verify.py CANDIDATE_ROOT
  Exit 0 only when every vendored file matches MANIFEST.json and the candidate passes the guard. Prints PASS or FAIL.

The guard job checks out main into .trusted-main and runs this file from there, so the checker and the manifest come from
the base, not from the candidate. The candidate tree is copied (never executed) and its workflows and files are data.
"""
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

VENDOR = Path(__file__).resolve().parent / "vendor" / "prod-94ef337"
sys.path.insert(0, str(VENDOR))
import artifact_guard as ag  # noqa: E402  (vendored production module, stdlib plus PyYAML)

# gate.yml is excluded from the scan: trusted_gate.py refuses any PR that changes it (raw SHA-256), so only the
# base copy can run. Without the exclusion its trusted action (create-github-app-token) would fail the allowlist.
TRUSTED_WORKFLOW = Path(".github/workflows/gate.yml")


def blob_sha1(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def verify_vendor(vendor=VENDOR):
    """Every vendored file must match its recorded blob SHA-1 and SHA-256. Anything else fails closed."""
    manifest = json.loads((vendor / "MANIFEST.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        data = (vendor / entry["name"]).read_bytes()
        if blob_sha1(data) != entry["blob_sha1"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("vendored file differs from MANIFEST.json: " + entry["name"])
    return manifest


def check_candidate(root):
    """Run the production upload and placement checks on a copy of the candidate tree. Raises ValueError on failure."""
    source = Path(root)
    ci = source / ".github" / "workflows" / "ci.yml"
    if ci.is_symlink() or not ci.is_file():
        raise ValueError("candidate ci.yml missing or not a regular file")
    with tempfile.TemporaryDirectory(prefix="guard-verify-") as scratch:
        tree = Path(scratch) / "tree"
        # symlinks=True keeps links as links, so the guard sees them and refuses them.
        shutil.copytree(source, tree, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        (tree / TRUSTED_WORKFLOW).unlink(missing_ok=True)
        # check_upload_artifacts refuses a tree with no upload step (it cannot establish the upload set), so it runs
        # only when some candidate workflow has one. An empty upload set is checked by check_guard_placement.
        uploads = sum(len(ag.upload_patterns(p.read_text(encoding="utf-8"))) for p in ag._workflow_files(tree))
        if uploads:
            ag.check_upload_artifacts(tree)
        ag.check_guard_placement(tree)


def main(argv):
    if len(argv) != 2:
        raise ValueError("usage: guard_verify.py CANDIDATE_ROOT")
    verify_vendor()
    check_candidate(argv[1])
    print("PASS guard-verify: vendored artifact_guard matches MANIFEST.json; candidate passes upload and placement checks")
    print("NOT_VERIFIED: provenance_guard, ROM and build checks (see tools/vendor/prod-94ef337/MANIFEST.json)")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (ValueError, OSError) as error:
        print("FAIL: " + str(error))
        raise SystemExit(1)
