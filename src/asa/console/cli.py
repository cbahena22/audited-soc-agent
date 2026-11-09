"""`asa console build [--runs out/runs/<run_id>] [--out out/console] [--code-base URL]`.

Registered by `asa.cli.build_parser` through `add_parser`; the handler is set as the `handler` default.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Callable

from ..common import RUN_ID, Repo, UsageError, check_id, clean_text
from .build import build
from .pages import CODE_BASE

OUT_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RESERVED = ("runs", "ledger", "partial")  # folders under out/ that hold run data, never a console


def say(line: str) -> None:
    print(clean_text(line), flush=True)


def add_parser(sub: argparse._SubParsersAction) -> None:
    con = sub.add_parser("console", help="the static demo console (no server, no network, no script)")
    con_sub = con.add_subparsers(dest="console_command", required=True)
    b = con_sub.add_parser("build", help="build the static site from one run folder (exit 1 if a trail does not verify)")
    b.add_argument("--runs", help="out/runs/<run_id> (default: the newest run)")
    b.add_argument("--out", default="out/console", help="output folder inside out/ (default out/console)")
    b.add_argument("--code-base", default=CODE_BASE, help="where code links point, https://github.com/<login>/audited-soc-agent/blob/<tag>/")
    b.set_defaults(handler=cmd_console)


def newest_run(repo: Repo) -> Path:
    root = repo.path("out", "runs")
    names = sorted(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink() and RUN_ID.fullmatch(p.name)) \
        if root.is_dir() else []
    if not names:
        raise UsageError("no run in out/runs/ yet: run `asa demo` or `asa investigate --mock` first")
    return repo.path("out", "runs", names[-1])


def _inside(repo: Repo, text: str, what: str) -> tuple[str, ...]:
    """The parts of `text` below out/, checked (exit 2 when it leaves out/ or names an odd folder)."""
    if not isinstance(text, str) or not text or len(text) > 400:
        raise UsageError(f"bad {what}")
    path = Path(text)
    try:
        parts = (path if path.is_absolute() else repo.base / path).resolve().relative_to(repo.path("out")).parts
    except ValueError:
        raise UsageError(f"bad {what}: it must be a folder inside out/") from None
    if not parts or not all(OUT_PART.fullmatch(p) for p in parts):
        raise UsageError(f"bad {what}: a folder inside out/ named with letters, digits, . _ -")
    return parts


def runs_arg(repo: Repo, text: str | None) -> Path:
    if text is None:
        return newest_run(repo)
    parts = _inside(repo, text, "--runs")
    if len(parts) != 2 or parts[0] != "runs":
        raise UsageError("bad --runs: expected out/runs/<run_id>")
    return repo.path("out", "runs", check_id(RUN_ID, parts[1], "run id"))


def out_arg(repo: Repo, text: str) -> Path:
    parts = _inside(repo, text, "--out")
    if parts[0] in RESERVED:
        raise UsageError(f"bad --out: out/{parts[0]}/ holds run data; pick another folder, e.g. out/console")
    return repo.path("out", *parts, write=True)


def report(result: dict, echo: Callable[[str], None] = say) -> int:
    trails = result["trails"]
    echo(f"console: {result['pages']} pages for {result['alerts']} alerts of run {result['run']}; trails: "
         f"{len(trails['verified'])} verified, {len(trails['failed'])} failed, {len(trails['not_checked'])} not checked")
    for alert_id in trails["failed"]:
        echo(f"trail of {alert_id} does NOT verify (see its audit page)")
    for name, reason in sorted(result["skipped"].items()):
        echo(f"skipped {name}: {reason}")
    echo(f"open {result['out']}/index.html")
    return 1 if trails["failed"] else 0


def cmd_console(args: argparse.Namespace, repo: Repo) -> int:
    return report(build(repo, runs_arg(repo, args.runs), out_arg(repo, args.out), code_base=args.code_base))
