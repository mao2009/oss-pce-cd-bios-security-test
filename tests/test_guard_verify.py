import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "tools")
import guard_verify as gv  # noqa: E402

# Mutation and temp trees go under SECTEST_TMP when set (the worker's scratchpad), otherwise the system temp.
TMP = os.environ.get("SECTEST_TMP") or None
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
CLEAN_CI = (
    "name: ci\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n"
    "  guard-verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo nothing to publish\n"
)
ELF = b"\x7fELF" + b"\x00" * 60


def upload_ci(path):
    return (
        "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n"
        "      - uses: " + UPLOAD + "\n        with:\n          name: out\n          path: " + path + "\n"
    )


def tree(files):
    """A fresh candidate tree under TMP. files maps a relative path to bytes or str. Caller removes it."""
    root = Path(tempfile.mkdtemp(dir=TMP))
    files = {".github/workflows/ci.yml": CLEAN_CI, **files}
    for name, data in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return root


class VendorTests(unittest.TestCase):
    def test_vendored_files_match_manifest(self):
        gv.verify_vendor()

    def test_mutated_vendored_copy_is_detected(self):
        # Mutation test: a one-line change in a copy of artifact_guard.py must fail verify_vendor, and nothing else.
        needle = 'raise ValueError("artifact guard: linked executable or unsafe entry would be uploaded: "'
        with tempfile.TemporaryDirectory(dir=TMP) as scratch:
            vendor = Path(scratch) / "vendor"
            shutil.copytree(gv.VENDOR, vendor)
            target = vendor / "artifact_guard.py"
            text = target.read_text(encoding="utf-8")
            self.assertEqual(text.count(needle), 1, "mutation needle must match exactly once")
            target.write_text(text.replace(needle, "pass  # mutated: " + needle), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "differs from MANIFEST.json: artifact_guard.py"):
                gv.verify_vendor(vendor)

    def test_unmutated_vendored_copy_passes(self):
        with tempfile.TemporaryDirectory(dir=TMP) as scratch:
            vendor = Path(scratch) / "vendor"
            shutil.copytree(gv.VENDOR, vendor)
            gv.verify_vendor(vendor)

    def test_vendored_files_have_no_carriage_return(self):
        # -text in .gitattributes keeps LF on every OS, so the hashed bytes are the blob bytes everywhere.
        for entry in gv.json.loads((gv.VENDOR / "MANIFEST.json").read_text(encoding="utf-8"))["files"]:
            self.assertNotIn(b"\r", (gv.VENDOR / entry["name"]).read_bytes(), entry["name"])

    def mutated_vendor(self, scratch, name, mutate):
        vendor = Path(scratch) / "vendor"
        shutil.copytree(gv.VENDOR, vendor)
        target = vendor / name
        target.write_bytes(mutate(target.read_bytes()))
        return vendor

    def test_one_byte_change_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=TMP) as scratch:
            vendor = self.mutated_vendor(scratch, "check.py", lambda b: b[:-1] + bytes([b[-1] ^ 0x01]))
            with self.assertRaisesRegex(ValueError, "differs from MANIFEST.json: check.py"):
                gv.verify_vendor(vendor)

    def test_line_ending_conversion_is_rejected(self):
        # A CRLF checkout of a vendored file must fail closed, not be normalized.
        with tempfile.TemporaryDirectory(dir=TMP) as scratch:
            vendor = self.mutated_vendor(scratch, "environment.py", lambda b: b.replace(b"\n", b"\r\n"))
            with self.assertRaisesRegex(ValueError, "differs from MANIFEST.json: environment.py"):
                gv.verify_vendor(vendor)

    def test_manifest_hash_edit_is_rejected(self):
        # Editing only the manifest's recorded hash must fail, because the file no longer matches it.
        with tempfile.TemporaryDirectory(dir=TMP) as scratch:
            vendor = Path(scratch) / "vendor"
            shutil.copytree(gv.VENDOR, vendor)
            manifest = vendor / "MANIFEST.json"
            text = manifest.read_text(encoding="utf-8")
            needle = "946a8589b62e9e96817756369050e9a3d7f9488550e2456d557a648c5fb206d2"
            self.assertEqual(text.count(needle), 1, "mutation needle must match exactly once")
            manifest.write_text(text.replace(needle, "0" * 64), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "differs from MANIFEST.json: artifact_guard.py"):
                gv.verify_vendor(vendor)


class CandidateTests(unittest.TestCase):
    def check(self, files):
        root = tree(files)
        try:
            gv.check_candidate(root)
        finally:
            shutil.rmtree(root, ignore_errors=False)   # our own temp tree only

    def test_clean_candidate_passes(self):
        self.check({})

    def test_upload_of_executable_fails(self):
        with self.assertRaisesRegex(ValueError, "linked executable or unsafe entry"):
            self.check({"build/out.elf": ELF, ".github/workflows/ci.yml": upload_ci("build/out.elf")})

    def test_upload_of_unlisted_action_fails(self):
        text = upload_ci("build/out.txt").replace(UPLOAD, "acme/publisher@v1")
        with self.assertRaisesRegex(ValueError, "not on the allowlist"):
            self.check({"build/out.txt": "ok", ".github/workflows/ci.yml": text})

    def test_release_route_fails(self):
        text = CLEAN_CI.replace("echo nothing to publish", "gh release upload v1 build/out.bin")
        with self.assertRaisesRegex(ValueError, "unsupported upload-artifact reference"):
            self.check({".github/workflows/ci.yml": text})

    def test_added_workflow_with_upload_of_executable_fails(self):
        # The candidate may add a second workflow; it is scanned too, not only ci.yml.
        with self.assertRaisesRegex(ValueError, "linked executable or unsafe entry"):
            self.check({"build/out.elf": ELF, ".github/workflows/publish.yml": upload_ci("build/out.elf")})

    def test_symlink_to_executable_fails(self):
        root = tree({"build/out.elf": ELF, ".github/workflows/ci.yml": upload_ci("build/link.bin")})
        try:
            try:
                (root / "build" / "link.bin").symlink_to(root / "build" / "out.elf")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks need privilege on this host")
            with self.assertRaises(ValueError):
                gv.check_candidate(root)
        finally:
            shutil.rmtree(root)

    def test_missing_ci_fails(self):
        root = Path(tempfile.mkdtemp(dir=TMP))
        try:
            with self.assertRaisesRegex(ValueError, "candidate ci.yml missing"):
                gv.check_candidate(root)
        finally:
            shutil.rmtree(root)


class WiringTests(unittest.TestCase):
    def test_guard_verify_job_runs_the_real_check_not_an_echo(self):
        import yaml   # PyYAML is pinned in tools/requirements-lint.txt

        jobs = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        runs = [s.get("run", "") for s in jobs["guard-verify"]["steps"]]
        self.assertTrue(any("guard_verify.py" in r for r in runs), runs)
        self.assertFalse(any("echo guard" in r or "echo verify" in r for r in runs), runs)
        # The checker must come from the trusted main checkout, not from the candidate.
        self.assertTrue(any(".trusted-main/tools/guard_verify.py" in r for r in runs), runs)


if __name__ == "__main__":
    unittest.main()
