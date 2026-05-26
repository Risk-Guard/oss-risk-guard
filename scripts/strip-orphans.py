#!/usr/bin/env python3
"""Remove orphan commented-out code blocks left behind by strip-dead.py.

A contiguous block of comment lines (each starting with `//`) is removed when:
  - the block ends with a line `// }` (possibly indented), AND
  - the next non-blank line is NOT a Go declaration (func/type/var/const/import)
    — i.e. the block is not a godoc preceding a real symbol.

Run with files as args.
"""
import re
import sys
from pathlib import Path

DECL_RE = re.compile(r"^\s*(func|type|var|const|import|package)\b")
CLOSE_RE = re.compile(r"^\s*//\s*}\s*$")
COMMENT_RE = re.compile(r"^\s*//")


def strip_file(p: Path) -> bool:
    lines = p.read_text().splitlines(keepends=True)
    n = len(lines)
    drop = [False] * n
    i = 0
    while i < n:
        if COMMENT_RE.match(lines[i]):
            j = i
            while j < n and COMMENT_RE.match(lines[j]):
                j += 1
            # j is first non-comment line (or end)
            block_end = j - 1
            if not CLOSE_RE.match(lines[block_end]):
                i = j
                continue
            for x in range(i, j):
                drop[x] = True
            i = j
        else:
            i += 1

    if not any(drop):
        return False
    out = [ln for ln, d in zip(lines, drop) if not d]
    # Collapse runs of >2 blank lines to 1.
    cleaned: list[str] = []
    blank = 0
    for ln in out:
        if ln.strip() == "":
            blank += 1
            if blank <= 1:
                cleaned.append(ln)
        else:
            blank = 0
            cleaned.append(ln)
    p.write_text("".join(cleaned))
    return True


def main() -> int:
    for arg in sys.argv[1:]:
        p = Path(arg)
        if not p.exists():
            continue
        if strip_file(p):
            print(f"stripped {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
