"""Render the buyer's checklist table of the README from checklist/checklist.json.

    python tools/render_checklist.py            rewrite the table in README.md in place
    python tools/render_checklist.py --check    exit 1 if README.md does not match checklist.json (tests/test_docs_checklist.py does the same)

The table is the block of lines starting with `|` under the heading `## The buyer's checklist`. Stdlib only, offline.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADING = "## The buyer's checklist"
HEADER = ["| # | Question | Answer, and where it stops | See it, code, test |", "|---|---|---|---|"]
VIEW = re.compile(r"(?P<page>queue|about|case|trust|audit)(?::(?P<alert>A-\d{3}))?(?:#(?P<part>[a-z]+))?")


def view_text(view: str) -> str:
    """`case:A-007#injection` -> `console, case A-007 › injection` (the console grammar of checklist.json)."""
    m = VIEW.fullmatch(view)
    if not m:
        raise ValueError(f"checklist: bad console_view {view!r}")
    words = [m["page"]] + ([m["alert"]] if m["alert"] else [])
    return "console: " + " ".join(words) + (f" › {m['part']}" if m["part"] else "")


def link(ref: str) -> str:
    """`src/asa/tools.py::Dataset.call` -> a relative Markdown link to the file, labelled with the symbol."""
    path, _, symbol = ref.partition("::")
    return f"[`{symbol or path}`]({path})"


def cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def render(rows: list[dict]) -> str:
    lines = list(HEADER)
    for r in rows:
        see = [view_text(r["console_view"])]
        see += ["code: " + ", ".join(link(c) for c in r["code"])]
        see += ["test: " + ", ".join(link(t) for t in r["tests"])]
        lines.append(f"| {r['id']} | **{cell(r['question'])}** | {cell(r['answer'])} *Limit:* {cell(r['limits'])} | " + "<br>".join(see) + " |")
    return "\n".join(lines)


def load_rows(root: Path = ROOT) -> list[dict]:
    return json.loads((root / "checklist" / "checklist.json").read_text(encoding="utf-8"))


def table_span(lines: list[str]) -> tuple[int, int]:
    """Index range [start, end) of the table lines under the checklist heading."""
    if HEADING not in lines:
        raise SystemExit(f"render_checklist: README.md has no line {HEADING!r}")
    i = lines.index(HEADING) + 1
    while i < len(lines) and not lines[i].startswith("|"):
        if lines[i].startswith("## "):
            raise SystemExit("render_checklist: no table under the checklist heading")
        i += 1
    j = i
    while j < len(lines) and lines[j].startswith("|"):
        j += 1
    return i, j


def current_table(readme: str) -> str:
    lines = readme.split("\n")
    i, j = table_span(lines)
    return "\n".join(lines[i:j])


def rewritten(readme: str, rows: list[dict]) -> str:
    lines = readme.split("\n")
    i, j = table_span(lines)
    return "\n".join(lines[:i] + render(rows).split("\n") + lines[j:])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 when README.md is out of date")
    args = ap.parse_args(argv)
    path = ROOT / "README.md"
    readme = path.read_text(encoding="utf-8")
    new = rewritten(readme, load_rows())
    if args.check:
        if new != readme:
            print("README.md checklist table is out of date: run python tools/render_checklist.py", file=sys.stderr)
            return 1
        print("README.md checklist table matches checklist/checklist.json")
        return 0
    if new != readme:
        path.write_text(new, encoding="utf-8", newline="\n")
        print("README.md checklist table rewritten")
    else:
        print("README.md checklist table already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
