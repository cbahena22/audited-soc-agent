"""Shift report (minimal): `asa shift-report --since <iso>` over out/runs/ -> Markdown with three lists, $0, no model.

  Open     the latest run of an alert says needs_human
  Changed  the verdict differs between runs of one alert
  Waiting  recommended actions of the latest run that no person has approved (dry run)
Model-written text (summaries, targets) is cleaned and escaped so it cannot add Markdown structure or terminal codes.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .actions import approvals, recommended
from .common import ALERT_ID, RUN_ID, Repo, UsageError, clean_text, read_json
from .prompt import VERDICTS
from .tools import parse_time

_MD = re.compile(r"([\\`*_{}\[\]<>()#+!|~])")


def md(text: Any, limit: int = 160) -> str:
    """One line of plain text for Markdown: control characters cleaned, whitespace collapsed, markup escaped."""
    flat = " ".join(clean_text(text).split())
    if len(flat) > limit:
        flat = flat[:limit] + "..."
    return _MD.sub(r"\\\1", flat)


def since_arg(value: str) -> datetime:
    try:
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError
        since = parse_time(value)
        if since is None:
            raise ValueError
        return since
    except (ValueError, OverflowError):
        raise UsageError("bad --since: an ISO 8601 time such as 2026-10-27T00:00:00Z") from None


def run_time(run_id: str) -> datetime | None:
    """The run's start time from its id, or None for an id that matches the pattern but is no real time."""
    try:
        return datetime.strptime(run_id[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def collect(repo: Repo, since: datetime) -> list[dict]:
    """Every finished alert run (verdict.json present) in out/runs/ at or after `since`, oldest first."""
    root = repo.path("out", "runs")
    runs = []
    if not root.is_dir():
        return runs
    for run in sorted(p for p in root.iterdir() if p.is_dir() and RUN_ID.fullmatch(p.name)):
        started = run_time(run.name)
        if started is None or started < since:
            continue
        for alert_dir in sorted(p for p in run.iterdir() if p.is_dir() and ALERT_ID.fullmatch(p.name)):
            if not (alert_dir / "verdict.json").is_file():
                continue  # stopped before a verdict (budget stop, API error)
            verdict = read_json(alert_dir / "verdict.json", f"{run.name}/{alert_dir.name}/verdict.json")
            if not isinstance(verdict, dict) or verdict.get("verdict") not in VERDICTS:
                continue
            runs.append({"run_id": run.name, "alert_id": alert_dir.name, "dir": alert_dir, "verdict": verdict})
    return runs


def build(repo: Repo, since: datetime) -> str:
    runs = collect(repo, since)
    by_alert: dict[str, list[dict]] = {}
    for r in runs:
        by_alert.setdefault(r["alert_id"], []).append(r)
    latest = {a: rs[-1] for a, rs in sorted(by_alert.items())}

    open_items = [f"- {a} (run {r['run_id']}): {md(r['verdict'].get('summary'))}"
                  for a, r in latest.items() if r["verdict"]["verdict"] == "needs_human"]
    changed = [f"- {a}: " + " -> ".join(f"{r['verdict']['verdict']} ({r['run_id']})" for r in rs)
               for a, rs in sorted(by_alert.items()) if len({r["verdict"]["verdict"] for r in rs}) > 1]
    waiting = []
    for a, r in latest.items():
        done = approvals(r["dir"])
        for action in recommended(r["dir"]):
            if action["id"] not in done:
                waiting.append(f"- {a} {action['id']} {md(action.get('action'), 30)} on {md(action.get('target'), 100)} "
                               f"(run {r['run_id']}): {md(action.get('reason'))}")

    stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [f"# Shift report since {stamp}", "",
             f"{len(runs)} alert runs in {len({r['run_id'] for r in runs})} run folder(s), {len(latest)} alerts. "
             "Approvals are dry runs: nothing was sent.", ""]
    for title, items in (("Open (needs a person)", open_items), ("Changed between runs", changed),
                         ("Waiting for approval", waiting)):
        lines += [f"## {title}", "", *(items or ["None."]), ""]
    return "\n".join(lines)
