#!/usr/bin/env python3
"""Read `deadcode` output on stdin and comment out unreachable funcs.

Usage:
    deadcode ./src/... | python3 scripts/comment-dead.py [--limit N]
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

LINE_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s*unreachable func:\s*(?P<name>.+)$")


def parse_stdin(limit: int | None) -> list[tuple[str, int, str]]:
    entries: list[tuple[str, int, str]] = []
    for raw in sys.stdin:
        m = LINE_RE.match(raw.strip())
        if not m:
            continue
        entries.append((m["file"], int(m["line"]), m["name"]))
        if limit is not None and len(entries) >= limit:
            break
    return entries


def find_func_range(lines: list[str], decl_line_idx: int) -> tuple[int, int] | None:
    """Return (start_idx, end_idx) inclusive of the func to comment out.

    decl_line_idx is 0-based; deadcode reports the line of the func name.
    The `func` keyword is usually on the same line; walk back if needed.
    """
    start = decl_line_idx
    while start >= 0 and "func" not in lines[start]:
        start -= 1
    if start < 0:
        return None

    # Find first '{' from start onward (skip strings/comments crudely).
    depth = 0
    seen_open = False
    i = start
    while i < len(lines):
        line = lines[i]
        j = 0
        while j < len(line):
            ch = line[j]
            # Skip line comment.
            if ch == "/" and j + 1 < len(line) and line[j + 1] == "/":
                break
            # Skip block comment.
            if ch == "/" and j + 1 < len(line) and line[j + 1] == "*":
                end = line.find("*/", j + 2)
                if end == -1:
                    # multi-line block comment; scan forward
                    j = len(line)
                    i_block = i + 1
                    while i_block < len(lines) and "*/" not in lines[i_block]:
                        i_block += 1
                    # jump past it
                    if i_block < len(lines):
                        # set i to i_block and reset j past */
                        line = lines[i_block]
                        j = line.find("*/") + 2
                        i = i_block
                        continue
                    else:
                        return None
                else:
                    j = end + 2
                    continue
            # Skip strings.
            if ch in ('"', '`', "'"):
                quote = ch
                j += 1
                while j < len(line):
                    if line[j] == "\\" and quote != "`":
                        j += 2
                        continue
                    if line[j] == quote:
                        j += 1
                        break
                    j += 1
                continue
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
                if seen_open and depth == 0:
                    return (start, i)
            j += 1
        i += 1
    return None


def comment_range(lines: list[str], start: int, end: int) -> None:
    for k in range(start, end + 1):
        if lines[k].lstrip().startswith("//"):
            continue
        # preserve indent
        stripped = lines[k]
        indent_len = len(stripped) - len(stripped.lstrip(" \t"))
        indent = stripped[:indent_len]
        rest = stripped[indent_len:]
        lines[k] = f"{indent}// {rest}"


GO_IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def strip_strings_and_comments(src: str) -> str:
    out = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        if ch in ('"', "`"):
            quote = ch
            i += 1
            while i < n:
                if src[i] == "\\" and quote != "`":
                    i += 2
                    continue
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


IMPORT_LINE_RE = re.compile(r'^\s*(?:([A-Za-z_][A-Za-z0-9_]*|\.|_)\s+)?"([^"]+)"\s*$')


def comment_unused_imports(lines: list[str]) -> None:
    # Find import block(s).
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("//"):
            i += 1
            continue
        # Single-line import.
        m_single = re.match(r'^\s*import\s+(?:([A-Za-z_][A-Za-z0-9_]*|\.|_)\s+)?"([^"]+)"\s*$', line)
        if m_single:
            alias, path = m_single.group(1), m_single.group(2)
            name = alias or path.rsplit("/", 1)[-1]
            if alias not in (".", "_") and not _is_used(lines, name, skip_line=i):
                lines[i] = "// " + line if not line.lstrip().startswith("//") else line
            i += 1
            continue
        if re.match(r"^\s*import\s*\(\s*$", line):
            j = i + 1
            block_indices = []
            while j < len(lines) and not re.match(r"^\s*\)\s*$", lines[j]):
                block_indices.append(j)
                j += 1
            for k in block_indices:
                bline = lines[k]
                if bline.strip() == "" or bline.lstrip().startswith("//"):
                    continue
                m = IMPORT_LINE_RE.match(bline)
                if not m:
                    continue
                alias, path = m.group(1), m.group(2)
                if alias in (".", "_"):
                    continue
                name = alias or path.rsplit("/", 1)[-1]
                # account for hyphens in last segment -> Go disallows, but some packages
                # use a different package name than the path tail. Best-effort.
                if not _is_used(lines, name, skip_line=k):
                    indent = bline[: len(bline) - len(bline.lstrip())]
                    rest = bline[len(indent):]
                    lines[k] = f"{indent}// {rest}"
            i = j + 1
            continue
        i += 1


def _is_used(lines: list[str], name: str, skip_line: int) -> bool:
    pattern = re.compile(r"\b" + re.escape(name) + r"\.")
    # Also count appearances as the package selector (Name.Something) or bare ref
    bare = re.compile(r"\b" + re.escape(name) + r"\b")
    for idx, line in enumerate(lines):
        if idx == skip_line:
            continue
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        # crude: don't strip strings per line, but skip lines that look like import lines
        if IMPORT_LINE_RE.match(line):
            continue
        if pattern.search(line) or bare.search(line):
            # bare match could be inside a string; acceptable for best-effort
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=1, help="max entries to process (default: 1)")
    args = ap.parse_args()

    limit = args.limit if args.limit > 0 else None
    entries = parse_stdin(limit)
    if not entries:
        print("no unreachable entries on stdin", file=sys.stderr)
        return 0

    by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for f, ln, name in entries:
        by_file[f].append((ln, name))

    for fpath, items in by_file.items():
        p = Path(fpath)
        if not p.exists():
            print(f"skip (not found): {fpath}", file=sys.stderr)
            continue
        text = p.read_text()
        lines = text.splitlines(keepends=True)

        # Process in reverse line order so indices remain valid.
        items.sort(key=lambda x: x[0], reverse=True)
        for ln, name in items:
            rng = find_func_range(lines, ln - 1)
            if rng is None:
                print(f"  could not locate func body for {name} at {fpath}:{ln}", file=sys.stderr)
                continue
            start, end = rng
            comment_range(lines, start, end)
            print(f"commented {fpath}:{start+1}-{end+1} ({name})", file=sys.stderr)

        comment_unused_imports(lines)
        p.write_text("".join(lines))

    return 0


if __name__ == "__main__":
    sys.exit(main())
