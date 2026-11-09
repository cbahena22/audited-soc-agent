"""Build the console: read one run folder (out/runs/<run_id>/), render every page, write them to a folder under out/.

Deterministic: the same inputs give the same bytes (no clock, sorted everything). The audit trail of each alert is
checked while building, with `asa.audit.verify` when it is installed; the result is printed in the page banner.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Callable

from ..common import Repo, UsageError
from ..tools import Dataset
from . import load, pages

GENERATOR = "asa console build"
MANIFEST = "manifest.json"
PAGE_NAME = re.compile(r"^(index|about|checklist|(case|trust|audit)-A-\d{3})\.html$")
DEFAULT = object()  # "use asa.audit.verify when it exists"

Verify = Callable[[Path], Any]


def default_verify() -> Verify | None:
    try:
        from .. import audit  # the trust layer's hash chain; absent in builds without it
    except ImportError:
        return None
    fn = getattr(audit, "verify", None)
    return fn if callable(fn) else None


def _unpack(result: Any) -> tuple[Any, Any, Any]:
    """(ok, first_bad_seq, reason) from a tuple, a bool or an object with those attributes."""
    if isinstance(result, bool):
        return result, None, None
    if isinstance(result, (tuple, list)):
        padded = list(result) + [None, None, None]
        return padded[0], padded[1], padded[2]
    return getattr(result, "ok", None), getattr(result, "first_bad_seq", None), getattr(result, "reason", None)


def check_trail(run: load.AlertRun, verify: Verify | None) -> dict:
    """{state: verified | failed | not_checked, head, first_bad_seq, reason} for one alert's audit.jsonl."""
    head = load.trail_head(run.trail)
    if run.trail is None:
        reason = f"audit.jsonl {run.notes['audit.jsonl']}" if "audit.jsonl" in run.notes else "no audit.jsonl in the run folder"
        return {"state": "not_checked", "head": None, "first_bad_seq": None, "reason": reason}
    if verify is None:
        return {"state": "not_checked", "head": head, "first_bad_seq": None, "reason": "the audit module is not installed"}
    try:
        ok, bad, reason = _unpack(verify(run.run_dir))
    except Exception as exc:  # noqa: BLE001 - a verifier error is shown as "not checked", never as verified
        return {"state": "not_checked", "head": head, "first_bad_seq": None, "reason": f"verify raised {type(exc).__name__}"}
    if ok is True:
        return {"state": "verified", "head": head, "first_bad_seq": None, "reason": None}
    return {"state": "failed", "head": head, "first_bad_seq": bad, "reason": str(reason)[:200] if reason else "no reason given"}


def _checklist_rows(value: Any) -> Any:
    if isinstance(value, dict) and isinstance(value.get("rows"), list):
        return value["rows"]
    return value if isinstance(value, list) else None


def render_site(repo: Repo, runs_dir: Path, code_base: str = pages.CODE_BASE, verify: Any = DEFAULT) -> tuple[dict[str, str], dict]:
    """{file name: html} for every page plus a summary. Reads only; writes nothing."""
    if not pages.valid_code_base(code_base):
        raise UsageError("bad --code-base: expected https://github.com/<login>/audited-soc-agent/blob/<tag>/")
    verify = default_verify() if verify is DEFAULT else verify
    runs, skipped = load.load_run(runs_dir)
    data = Dataset(repo)
    results, _ = load.load_repo_json(repo, "evals/results.json")
    checklist, problem = load.load_repo_json(repo, "checklist", "checklist.json", shape=object)
    rows = _checklist_rows(checklist)
    if checklist is not None and rows is None:
        problem = "expected a list of rows"

    replay = next((r.verdict["replay_of"] for r in runs if isinstance(r.verdict.get("replay_of"), dict)), None) or {}
    site = pages.Site(run_id=runs_dir.name, recording=replay.get("recording"), model=replay.get("model"),
                      code_base=code_base, alert_ids={r.alert_id for r in runs})
    honesty = pages.honesty_lines(results)
    if honesty:
        site.honesty, site.honesty_source = honesty
    site.planted = pages.planted_counts(results, site.recording)

    files = {"index.html": pages.queue_page(site, runs, skipped, data.alerts),
             "checklist.html": pages.checklist_page(site, rows, problem),
             "about.html": pages.about_page(site)}
    states: dict[str, list[str]] = {"verified": [], "failed": [], "not_checked": []}
    for run in runs:
        alert = data.alerts.get(run.alert_id) or {}
        trail = check_trail(run, verify)
        states[trail["state"]].append(run.alert_id)
        files[f"case-{run.alert_id}.html"] = pages.case_console_page(site, run, alert, data, trail)
        files[f"trust-{run.alert_id}.html"] = pages.trust_page(site, run, alert, trail)
        files[f"audit-{run.alert_id}.html"] = pages.audit_page(site, run, alert, trail)
    summary = {"run": runs_dir.name, "alerts": len(runs), "pages": len(files), "skipped": skipped, "trails": states}
    return files, summary


def _encode(text: str) -> bytes:
    return text.encode("utf-8", "replace")  # a lone surrogate from model output becomes "?"


def write_site(repo: Repo, out_dir: Path, files: dict[str, str], run_id: str) -> None:
    """Replace an earlier console build in out_dir (never a folder that holds anything else)."""
    rel = repo.rel(out_dir) if out_dir.exists() and not out_dir.is_symlink() else "the output folder"
    if out_dir.is_symlink() or (out_dir.exists() and not out_dir.is_dir()):
        raise UsageError(f"refusing to write into {rel}: not a plain folder")
    if out_dir.exists():
        entries = sorted(out_dir.iterdir())
        marker = out_dir / MANIFEST
        if entries:
            try:
                ok = (marker.is_file() and not marker.is_symlink()
                      and json.loads(marker.read_text(encoding="utf-8")).get("generator") == GENERATOR)
            except (OSError, ValueError, AttributeError):
                ok = False
            if not ok:
                raise UsageError(f"refusing to write into {rel}: it is not empty and not an earlier console build")
        for entry in entries:
            if PAGE_NAME.fullmatch(entry.name) or entry.name == MANIFEST:
                if entry.is_dir() and not entry.is_symlink():
                    raise UsageError(f"refusing to write into {rel}: {entry.name} is a folder")
                entry.unlink()
    else:
        out_dir.mkdir(parents=True)
    blobs = {name: _encode(text) for name, text in sorted(files.items())}
    manifest = {"generator": GENERATOR, "run": run_id,
                "files": {name: hashlib.sha256(blob).hexdigest() for name, blob in blobs.items()}}
    blobs[MANIFEST] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    for name, blob in blobs.items():
        fd = os.open(out_dir / name, flags, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)


def build(repo: Repo, runs_dir: Path, out_dir: Path, code_base: str = pages.CODE_BASE, verify: Any = DEFAULT) -> dict:
    """Render and write the site. Returns the summary (pages, alerts, skipped, trail states, output folder)."""
    files, summary = render_site(repo, runs_dir, code_base, verify)
    write_site(repo, out_dir, files, runs_dir.name)
    return {**summary, "out": repo.rel(out_dir)}
