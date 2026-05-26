#!/usr/bin/env python3
"""Remove commented-out import lines inside `import (...)` blocks."""
import re
import sys
from pathlib import Path

IMPORT_OPEN = re.compile(r"^\s*import\s*\(\s*$")
IMPORT_CLOSE = re.compile(r"^\s*\)\s*$")
COMMENTED_IMPORT = re.compile(r'^\s*//\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"[^"]+"\s*$')
SINGLE_COMMENTED_IMPORT = re.compile(r'^\s*//\s*import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"[^"]+"\s*$')


def strip_file(p: Path) -> bool:
    lines = p.read_text().splitlines(keepends=True)
    out: list[str] = []
    in_block = False
    changed = False
    for ln in lines:
        if not in_block and IMPORT_OPEN.match(ln):
            in_block = True
            out.append(ln)
            continue
        if in_block and IMPORT_CLOSE.match(ln):
            in_block = False
            out.append(ln)
            continue
        if in_block and COMMENTED_IMPORT.match(ln):
            changed = True
            continue
        if SINGLE_COMMENTED_IMPORT.match(ln):
            changed = True
            continue
        out.append(ln)
    if changed:
        # collapse blank lines at top of import block
        text = "".join(out)
        text = re.sub(r"import \(\n(\s*\n)+", "import (\n", text)
        text = re.sub(r"(\n\s*\n)+\)", "\n)", text)
        p.write_text(text)
    return changed


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
