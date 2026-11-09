"""Recommended actions and dry-run approvals. Nothing here (or anywhere in the package) carries an action out.

`asa actions <run_dir>` lists the run's recommended actions with their citations and approval state.
`asa approve <ACT-id> --run <run_dir> --as <name>` appends one line to the run's approvals.jsonl:
  {id, by, at, status: "approved (dry run, not sent)"}. Approving the same action twice is a no-op with a message.
Each approval is also an `approval` line in the run's audit trail, actor `person:<name>`, written under the trail's lock
together with the approvals.jsonl line. The name is whatever --as says: there is no login behind it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .audit import AT, NAME, Trail, Writer
from .common import ACTION_ID, UsageError, append_jsonl, check_id, output_file, read_json, utc_now

APPROVER = re.compile(rf"^{NAME}$")
STATUS = "approved (dry run, not sent)"


def recommended(run_dir: Path) -> list[dict]:
    verdict = read_json(run_dir / "verdict.json", "verdict.json")
    actions = verdict.get("recommended_actions") if isinstance(verdict, dict) else None
    if not isinstance(actions, list):
        raise UsageError("verdict.json has no recommended_actions list")
    return [a for a in actions if isinstance(a, dict) and isinstance(a.get("id"), str) and ACTION_ID.fullmatch(a["id"])]


def approvals(run_dir: Path) -> dict[str, dict]:
    """The first approval line per action id (later duplicates cannot exist through `approve`)."""
    path = run_dir / "approvals.jsonl"
    found: dict[str, dict] = {}
    if not path.is_file():
        return found
    try:
        with path.open(encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
    except (OSError, ValueError, RecursionError) as exc:
        raise UsageError(f"cannot read approvals.jsonl: {type(exc).__name__}") from None
    for line in lines:
        if isinstance(line, dict) and isinstance(line.get("id"), str):
            found.setdefault(line["id"], line)
    return found


def action_lines(run_dir: Path) -> list[str]:
    done = approvals(run_dir)
    lines = []
    for a in recommended(run_dir):
        state = f"{STATUS} by {done[a['id']].get('by')}" if a["id"] in done else "waiting for a person"
        cites = ", ".join(str(c) for c in a.get("citations") or []) or "none"
        lines.append(f"{a['id']} {a.get('action')} {str(a.get('target'))[:100]}: {str(a.get('reason'))[:200]} "
                     f"[cites {cites}] - {state}")
    return lines or ["no recommended actions in this run"]


def approve(run_dir: Path, action_id: str, by: str, at: str | None = None) -> tuple[bool, str]:
    """Record a dry-run approval. Returns (written, message). `at` (UTC, 2026-10-28T09:00:00Z) is for scripted demos;
    a person's approval takes the current time."""
    check_id(ACTION_ID, action_id, "action id")
    if not isinstance(by, str) or not APPROVER.fullmatch(by):
        raise UsageError("bad --as: a role or name of letters, spaces and . ' - (at most 41 characters), e.g. \"Night Lead\"")
    if at is not None and (not isinstance(at, str) or not AT.fullmatch(at)):
        raise UsageError("bad approval time: expected UTC like 2026-10-28T09:00:00Z")
    if action_id not in {a["id"] for a in recommended(run_dir)}:
        raise UsageError(f"no action {action_id} in this run")
    trail = Trail.of(run_dir)
    if not trail.exists():  # a run folder made before audit trails: approvals.jsonl only
        return _approve(run_dir, action_id, by, at, None)
    with trail.writer() as writer:  # the duplicate check, the approvals line and the trail line under one lock
        return _approve(run_dir, action_id, by, at, writer)


def _approve(run_dir: Path, action_id: str, by: str, at: str | None, writer: Writer | None) -> tuple[bool, str]:
    done = approvals(run_dir)
    if action_id in done:
        return False, f"{action_id} is already {STATUS} by {done[action_id].get('by')}; nothing changed"
    line = {"id": action_id, "by": by, "at": at or utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"), "status": STATUS}
    append_jsonl(output_file(run_dir, "approvals.jsonl"), line)
    if writer is not None:
        writer.append("approval", f"person:{by}", f"{action_id} {STATUS}", line, at=line["at"])
    return True, f"{action_id} {STATUS} by {by}"
