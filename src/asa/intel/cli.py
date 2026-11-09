"""`asa intel <run_dir>`: register the subcommand with `add_parser(sub)` and run it with `run(args, repo)`."""
from __future__ import annotations

import argparse
from pathlib import Path

from ..common import Repo, UsageError, clean_text, run_dir_arg
from .enrich import DEFAULT_MAX_LOOKUPS, LABEL, MAX_LOOKUPS_LIMIT, enrich, summary
from .iocs import Ioc, defang


def add_parser(sub) -> argparse.ArgumentParser:
    p = sub.add_parser("intel", help="post-triage threat-intel enrichment of a run from synthetic fixtures ($0, no network)")
    p.add_argument("run_dir", help="out/runs/<run_id>/<alert_id>")
    p.add_argument("--fixtures", help="fixture folder inside data/ (default: data/intel/fixtures)")
    p.add_argument("--max-lookups", type=int, default=DEFAULT_MAX_LOOKUPS,
                   help=f"cap on provider lookups per run, 1 to {MAX_LOOKUPS_LIMIT} (default {DEFAULT_MAX_LOOKUPS})")
    p.set_defaults(handler=run)
    return p


def fixtures_arg(repo: Repo, text: str | None) -> Path | None:
    """A fixture folder named on the command line: it must be a real folder inside data/."""
    if text is None:
        return None
    if not isinstance(text, str) or len(text) > 400:
        raise UsageError("bad --fixtures: expected a folder inside data/")
    data_root = repo.path("data")
    path = Path(text)
    target = (path if path.is_absolute() else repo.base / path).resolve()
    if target == data_root or data_root not in target.parents or not target.is_dir():
        raise UsageError("bad --fixtures: expected an existing folder inside data/")
    return target


def run(args: argparse.Namespace, repo: Repo) -> int:
    run_dir = run_dir_arg(repo, args.run_dir)
    record = enrich(repo, run_dir, fixtures_arg(repo, args.fixtures), args.max_lookups)
    print(clean_text(f"{LABEL}; the verdict did not use it"), flush=True)
    for row in record["indicators"]:
        shown = defang(Ioc(row["type"], row["value"]))
        print(clean_text(f"{row['verdict']:<8} {row['rule']:<18} {row['type']:<7} {shown}  "
                         f"from {', '.join(row['from_event_ids'])}"), flush=True)
    s = summary(record)
    print(clean_text(f"{s['indicators']} indicators: {s['contain']} contain, {s['review']} review, {s['clear']} clear; "
                     f"wrote {record['run']}/intel.json"), flush=True)
    return 0
