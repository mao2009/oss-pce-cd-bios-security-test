import hashlib
import re
import sys
from pathlib import Path

GUARD_JOB = "  guard-verify:"
NEXT_JOB = re.compile(r"^  [A-Za-z0-9_-]+:$")
EXPECTED_GUARD_SHA256 = "0270421589ef19fe5707531e8ae20e49dbf12b5ec1457e7b6118470911080bdc"


def guard_block(text):
    lines = [line.rstrip() for line in text.splitlines()]
    if GUARD_JOB not in lines:
        return None
    start = lines.index(GUARD_JOB)
    block = [lines[start]]
    for line in lines[start + 1:]:
        if NEXT_JOB.match(line):
            break
        block.append(line)
    return "\n".join(block)


def verdict(candidate_root, head_sha, event_sha):
    if head_sha != event_sha:
        return "FAIL: head sha mismatch"
    path = Path(candidate_root) / ".github" / "workflows" / "ci.yml"
    if not path.is_file():
        return "FAIL: ci.yml missing"
    block = guard_block(path.read_text(encoding="utf-8"))
    if block is None:
        return "FAIL: guard-verify job missing"
    if "if:" in block:
        return "FAIL: guard-verify has if:"
    digest = hashlib.sha256(block.encode("utf-8")).hexdigest()
    if digest != EXPECTED_GUARD_SHA256:
        return "FAIL: guard-verify job changed (" + digest[:12] + ")"
    return "PASS"


if __name__ == "__main__":
    if len(sys.argv) == 3:
        head_sha = sys.argv[2]
        event_sha = head_sha
        result = verdict(sys.argv[1], head_sha, event_sha)
        print(result)
        sys.exit(0 if result == "PASS" else 1)
    sys.exit(2)
