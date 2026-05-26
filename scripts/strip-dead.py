#!/usr/bin/env python3
"""Remove blocks of commented-out Go funcs by tracking brace depth on the
commented (post-`//`) content."""
import re
import sys
from pathlib import Path

FUNC_RE = re.compile(r"^//\s*func\b")
COMMENT_RE = re.compile(r"^\s*//")


def comment_body(line: str) -> str:
    """Return text after the leading `//` (and one space), or '' if not a comment."""
    s = line.lstrip()
    if not s.startswith("//"):
        return ""
    return s[2:]


def count_braces(text: str) -> tuple[int, int]:
    """Count unescaped { and } outside strings/line-comments. Crude but fine for code."""
    opens = closes = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            break
        if c in ('"', "`", "'"):
            q = c
            i += 1
            while i < n:
                if text[i] == "\\" and q != "`":
                    i += 2
                    continue
                if text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "{":
            opens += 1
        elif c == "}":
            closes += 1
        i += 1
    return opens, closes


def strip_file(p: Path) -> bool:
    lines = p.read_text().splitlines(keepends=True)
    out: list[str] = []
    i = 0
    changed = False
    while i < len(lines):
        if FUNC_RE.match(lines[i].lstrip()):
            depth = 0
            j = i
            saw_open = False
            while j < len(lines) and COMMENT_RE.match(lines[j]):
                body = comment_body(lines[j])
                o, c = count_braces(body)
                depth += o - c
                if o > 0:
                    saw_open = True
                j += 1
                if saw_open and depth == 0:
                    break
            if saw_open:
                i = j
                changed = True
                continue
        out.append(lines[i])
        i += 1
    if changed:
        p.write_text("".join(out))
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
