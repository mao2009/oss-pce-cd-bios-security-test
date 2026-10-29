import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import gate_update as g  # noqa: E402

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)
BASE = "a" * 40
HEAD = "b" * 40
OTHER = "c" * 40
REPO = "mao2009/oss-pce-cd-bios-security-test"
CHANGED = [".github/workflows/gate.yml", "tools/trusted_gate.py"]
FILES = {p: ("content of " + p).encode() for p in CHANGED}
APPROVERS = {"owner-login"}


def pr(head=HEAD, base=BASE, number=40):
    return {
        "number": number, "state": "open",
        "base": {"ref": "main", "sha": base, "repo": {"full_name": REPO}},
        "head": {"sha": head},
    }


def approval(**over):
    rec = {
        "repo": REPO, "pr": 40, "base_sha": BASE, "head_sha": HEAD,
        "approvers": ["owner-login"],
        "approved_at": (NOW - timedelta(hours=1)).isoformat(),
        "files": {p: g.sha256_hex(FILES[p]) for p in CHANGED},
    }
    rec.update(over)
    return rec


def run(p=None, base_now=BASE, changed=None, files=None, rec="default", approvers=APPROVERS, checker=None):
    if rec == "default":
        rec = approval()
    return g.evaluate(
        p or pr(), base_now, CHANGED if changed is None else changed,
        FILES if files is None else files, rec, approvers,
        checker or (lambda f: True), NOW,
    )


class GateUpdatePositive(unittest.TestCase):
    def test_approved_update_passes(self):
        ok, reason = run()
        self.assertTrue(ok, reason)
        self.assertEqual(g.publish_conclusion(ok), "success")


class GateUpdateNegative(unittest.TestCase):
    def check(self, result, part):
        ok, reason = result
        self.assertFalse(ok, reason)
        self.assertIn(part, reason)
        self.assertEqual(g.publish_conclusion(ok), "failure")

    def test_outside_scope_is_not_an_update(self):
        files = dict(FILES, **{"src/x.c": b"x"})
        self.check(run(changed=CHANGED + ["src/x.c"], files=files), "outside update scope")

    def test_empty_or_duplicate_listing_rejected(self):
        self.check(run(changed=[]), "empty or contains duplicates")
        self.check(run(changed=CHANGED + CHANGED[:1]), "empty or contains duplicates")

    def test_stale_base_rejected(self):
        self.check(run(base_now=OTHER), "current main HEAD")

    def test_pr_base_not_current_rejected(self):
        self.check(run(p=pr(base=OTHER)), "current main HEAD")

    def test_old_success_for_old_head_rejected(self):
        # An approval and a passing result for an earlier head must not carry over to a new head.
        self.check(run(p=pr(head=OTHER)), "PR head moved after approval")

    def test_head_change_after_approval_rejected(self):
        rec = approval(head_sha=HEAD)
        self.check(run(p=pr(head=OTHER), rec=rec), "PR head moved after approval")

    def test_approval_for_other_base_rejected(self):
        # PR base and current main agree (OTHER); only the approval's base differs.
        self.check(run(p=pr(base=OTHER), base_now=OTHER), "different base SHA")

    def test_approval_for_other_pr_rejected(self):
        self.check(run(rec=approval(pr=41)), "different repository or PR")

    def test_approval_expired_rejected(self):
        stale = (NOW - timedelta(hours=25)).isoformat()
        self.check(run(rec=approval(approved_at=stale)), "approval expired")

    def test_future_approval_rejected(self):
        future = (NOW + timedelta(hours=1)).isoformat()
        self.check(run(rec=approval(approved_at=future)), "approval time invalid")

    def test_naive_approval_time_rejected(self):
        naive = (NOW - timedelta(hours=1)).replace(tzinfo=None).isoformat()
        self.check(run(rec=approval(approved_at=naive)), "approval time invalid")

    def test_untrusted_approver_rejected(self):
        self.check(run(rec=approval(approvers=["someone-else"])), "not from a trusted approver")

    def test_missing_approval_rejected(self):
        self.check(run(rec=None), "no owner approval record")

    def test_checker_tampering_after_approval_rejected(self):
        files = dict(FILES, **{"tools/trusted_gate.py": b"tampered"})
        self.check(run(files=files), "candidate file differs from approved content")

    def test_approval_not_covering_all_files_rejected(self):
        rec = approval(files={CHANGED[0]: g.sha256_hex(FILES[CHANGED[0]])})
        self.check(run(rec=rec), "does not cover exactly the changed files")

    def test_trusted_checker_rejection_propagates(self):
        self.check(run(checker=lambda f: False), "trusted checker rejected")

    def test_malformed_pr_fails_closed(self):
        self.check(g.evaluate({"number": 40}, BASE, CHANGED, FILES, approval(), APPROVERS,
                              lambda f: True, NOW), "missing a required field")


if __name__ == "__main__":
    unittest.main()
