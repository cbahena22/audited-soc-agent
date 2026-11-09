"""Safe reads for the console. Every file is a plain file (never a link) under a named root, size-capped, parsed as
strict JSON (no NaN / Infinity) and shape-checked. A missing or broken optional file becomes a note on the page,
never a traceback; the text inside is untrusted and is only ever rendered escaped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..common import ALERT_ID, Repo, UsageError

KB = 1024
CAPS = {"verdict.json": 1024 * KB, "check.json": 1024 * KB, "trust.json": 512 * KB, "intel.json": 2048 * KB,
        "approvals.jsonl": 512 * KB, "audit.jsonl": 8192 * KB, "checklist.json": 512 * KB, "results.json": 2048 * KB}
MAX_LINES = 20000      # audit.jsonl / approvals.jsonl lines read per alert
MAX_ALERTS = 500       # alert folders read per run
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Missing(Exception):
    """The optional file is not there."""


class Unreadable(Exception):
    """The file is there but cannot be used; the message is a short fixed reason, never file content."""


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed")


def read_bytes(path: Path, cap: int) -> bytes:
    if path.is_symlink():
        raise Unreadable("is a link")
    if not path.exists():
        raise Missing(path.name)
    if not path.is_file():
        raise Unreadable("not a plain file")
    if path.stat().st_size > cap:
        raise Unreadable(f"larger than {cap // KB} KB")
    with path.open("rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise Unreadable(f"larger than {cap // KB} KB")
    return data


def parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise Unreadable(f"not valid JSON ({type(exc).__name__})") from None


def load_json(path: Path, cap: int, shape: type = dict) -> Any:
    value = parse_json(read_bytes(path, cap))
    if not isinstance(value, shape):
        raise Unreadable(f"expected a JSON {'object' if shape is dict else 'list'}")
    return value


def load_jsonl(path: Path, cap: int) -> list[dict | None]:
    """One entry per non-empty line: the object, or None for a line that is not a JSON object (shown as unreadable)."""
    raw = read_bytes(path, cap)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Unreadable("not UTF-8") from None
    out: list[dict | None] = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        if len(out) >= MAX_LINES:
            raise Unreadable(f"more than {MAX_LINES} lines")
        try:
            value = json.loads(line, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            value = None
        out.append(value if isinstance(value, dict) else None)
    return out


@dataclass
class AlertRun:
    """What the console knows about one alert of the run. Optional files are None when missing; `notes` names the
    files that were present but unreadable, with a fixed reason."""
    alert_id: str
    run_dir: Path
    verdict: dict
    check: dict | None = None
    trust: dict | None = None
    intel: dict | None = None
    approvals: dict[str, dict] = field(default_factory=dict)
    trail: list[dict | None] | None = None
    notes: dict[str, str] = field(default_factory=dict)


def _optional(run: AlertRun, name: str, loader: Callable[[], Any]) -> Any:
    try:
        return loader()
    except Missing:
        return None
    except Unreadable as exc:
        run.notes[name] = str(exc)
        return None


def first_approvals(lines: list[dict | None]) -> dict[str, dict]:
    """The first approval line per action id (the same rule as `asa actions`)."""
    found: dict[str, dict] = {}
    for line in lines:
        if isinstance(line, dict) and isinstance(line.get("id"), str):
            found.setdefault(line["id"], line)
    return found


def load_alert(run_dir: Path) -> AlertRun:
    """One alert folder. A missing or broken verdict.json makes the whole alert unusable (Unreadable / Missing)."""
    verdict = load_json(run_dir / "verdict.json", CAPS["verdict.json"])
    if verdict.get("alert_id") != run_dir.name:
        raise Unreadable("belongs to another alert")
    run = AlertRun(run_dir.name, run_dir, verdict)
    run.check = _optional(run, "check.json", lambda: load_json(run_dir / "check.json", CAPS["check.json"]))
    run.trust = _optional(run, "trust.json", lambda: load_json(run_dir / "trust.json", CAPS["trust.json"]))
    run.intel = _optional(run, "intel.json", lambda: load_json(run_dir / "intel.json", CAPS["intel.json"]))
    approvals = _optional(run, "approvals.jsonl", lambda: load_jsonl(run_dir / "approvals.jsonl", CAPS["approvals.jsonl"]))
    run.approvals = first_approvals(approvals or [])
    run.trail = _optional(run, "audit.jsonl", lambda: load_jsonl(run_dir / "audit.jsonl", CAPS["audit.jsonl"]))
    return run


def load_run(runs_dir: Path) -> tuple[list[AlertRun], dict[str, str]]:
    """All alert folders of one run, sorted by alert id, plus {alert folder: reason} for the ones that could not be read."""
    if runs_dir.is_symlink() or not runs_dir.is_dir():
        raise UsageError("the run folder is missing or is a link")
    runs, skipped = [], {}
    for path in sorted(runs_dir.iterdir(), key=lambda p: p.name):
        if not ALERT_ID.fullmatch(path.name):
            continue
        if len(runs) + len(skipped) >= MAX_ALERTS:
            raise UsageError(f"more than {MAX_ALERTS} alert folders in one run")
        if path.is_symlink() or not path.is_dir():
            skipped[path.name] = "not a plain folder"
            continue
        try:
            runs.append(load_alert(path))
        except Missing:
            skipped[path.name] = "no verdict.json"
        except Unreadable as exc:
            skipped[path.name] = f"verdict.json {exc}"
    if not runs:
        raise UsageError("no readable alert folder in the run (expected out/runs/<run_id>/A-NNN/verdict.json)")
    return runs, skipped


def load_repo_json(repo: Repo, root: str, *parts: str, shape: type = dict) -> tuple[Any, str | None]:
    """An optional repo file (checklist, eval results): (value, None), (None, None) when missing, (None, reason) when broken."""
    path = repo.path(root, *parts)
    try:
        return load_json(path, CAPS.get(path.name, 512 * KB), shape), None
    except Missing:
        return None, None
    except Unreadable as exc:
        return None, str(exc)


def trail_head(trail: list[dict | None] | None) -> str | None:
    """The sha256 of the last trail line, when it looks like one."""
    if not trail or not isinstance(trail[-1], dict):
        return None
    head = trail[-1].get("sha256")
    return head if isinstance(head, str) and HEX64.fullmatch(head) else None
