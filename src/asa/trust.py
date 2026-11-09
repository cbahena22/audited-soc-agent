"""The trust report: one run folder's answers to "why should I trust this verdict?", built only from files code wrote
and the audit trail that vouches for them. `asa trust <run_dir>` writes trust.json and prints a short summary.

It refuses (exit 1) a run whose audit trail does not verify: a report about records that may have been edited
would be worse than no report. Every number is counted from the run folder; nothing comes from the model's own words
except what the verdict lists (claims, reported injections, recommended actions), and those are counted, not quoted.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from . import audit
from .actions import APPROVER
from .checker import read_transcript, seen_event_ids
from .common import Repo, UsageError, clean_text, output_file, read_json, recording_date, write_json
from .evals import UNSUPPORTED, followed_count

INTEL_VERDICTS = ("contain", "review", "clear")
LIMITS = (
    "Synthetic data: the alerts, events and answer key are made up for this demo, and the run is one recording (n = 30).",
    "The evidence checker proves that a quoted text exists in the cited event, not that the conclusion is right.",
    "Planted injections are a known set of 6 texts; reporting them all does not prove resistance to new wording.",
    "followed counts a verdict or action that matches what a planted text asked for, even when that is also the "
    "expected result, so it can over-count but never under-count.",
    "Approver names are self-declared: asa approve --as is free text and there is no login behind it.",
    "Approvals are dry runs: nothing is executed anywhere, by this code or by the model.",
    "The audit trail is tamper-evident, not tamper-proof: rewriting the whole trail is caught only against a head "
    "hash kept somewhere else.",
    "Threat-intel verdicts, when present, are post-triage enrichment from synthetic provider answers; the verdict did "
    "not use them.",
)
_BUDGET = re.compile(r", budget \$(\d{1,7}\.\d{2})$")


class TrustRefused(Exception):
    """The run's records cannot be vouched for (the trail does not verify): no report is written (exit 1)."""


def _cited(verdict: dict) -> set[str]:
    ids: set[str] = set()
    for claim in verdict.get("claims") or []:
        if isinstance(claim, dict):
            ids.update(e for e in claim.get("citations") or [] if isinstance(e, str))
            ids.update(q.get("event_id") for q in claim.get("quotes") or [] if isinstance(q, dict) and isinstance(q.get("event_id"), str))
    for action in verdict.get("recommended_actions") or []:
        if isinstance(action, dict):
            ids.update(e for e in action.get("citations") or [] if isinstance(e, str))
    return ids


def _key_entry(repo: Repo, alert_id: str) -> dict | None:
    path = repo.path("evals/answer_key.json")
    if not path.is_file():
        return None
    key = read_json(path, "evals/answer_key.json")
    entry = key.get(alert_id) if isinstance(key, dict) else None
    return entry if isinstance(entry, dict) else None


def _evidence(run_dir: Path, verdict: dict) -> dict:
    claims = len(verdict.get("claims") or [])
    if not (run_dir / "check.json").is_file():
        return {"claims": claims, "supported": None, "findings_by_kind": {}, "checked": False, "with_key": None}
    check = read_json(run_dir / "check.json", "check.json")
    findings = [f for f in check.get("findings") or [] if isinstance(f, dict)] if isinstance(check, dict) else []
    unsupported = {f.get("claim_index") for f in findings if f.get("kind") in UNSUPPORTED and isinstance(f.get("claim_index"), int)}
    kinds = Counter(str(f.get("kind")) for f in findings)
    return {"claims": claims, "supported": claims - len(unsupported), "findings_by_kind": dict(sorted(kinds.items())),
            "checked": True, "with_key": bool(check.get("with_key"))}


def _injection(verdict: dict, entry: dict | None) -> dict:
    reports = [r for r in verdict.get("injection_reports") or [] if isinstance(r, dict)]
    reported = [{"event_id": r.get("event_id"), "field": r.get("field")} for r in reports]
    planted = entry.get("planted_injection_event_ids") if entry else None
    planted = [e for e in planted if isinstance(e, str)] if isinstance(planted, list) else None
    ids = {r["event_id"] for r in reported}
    return {"reported": reported,
            "planted_known": None if planted is None else bool(planted),
            "planted": None if planted is None else len(planted),
            "planted_reported": None if planted is None else sum(e in ids for e in planted),
            "followed": followed_count(entry, verdict) if entry else None}


def _approvals(run_dir: Path) -> list[dict]:
    path = run_dir / "approvals.jsonl"
    if not path.is_file():
        return []
    lines = audit._read_lines(path, "approvals.jsonl")
    if isinstance(lines, audit.AuditError):
        raise lines
    # only names `asa approve --as` accepts: a hand-written approvals line can hold anything, and the console shows it
    return [{"id": a.get("id"), "by": a["by"], "at": a.get("at")} for a in lines
            if isinstance(a, dict) and isinstance(a.get("by"), str) and APPROVER.fullmatch(a["by"])]


def _intel(run_dir: Path) -> dict | None:
    if not (run_dir / "intel.json").is_file():
        return None
    intel = read_json(run_dir / "intel.json", "intel.json")
    indicators = intel.get("indicators") if isinstance(intel, dict) else None
    indicators = [i for i in indicators if isinstance(i, dict)] if isinstance(indicators, list) else []
    counts = Counter(i["verdict"] for i in indicators if isinstance(i.get("verdict"), str))
    return {"indicators": len(indicators), **{v: counts.get(v, 0) for v in INTEL_VERDICTS},
            "source": intel.get("source") if isinstance(intel, dict) else None}


def build(repo: Repo, run_dir: Path) -> dict:
    """The trust report of one run folder. Raises TrustRefused when the audit trail does not verify."""
    run_dir = Path(run_dir)
    ok, bad, why = audit.verify(run_dir)
    if not ok:
        raise TrustRefused("audit trail does not verify" + (f" at seq {bad}" if bad else "") + f": {why}")
    lines, _, _ = audit.read_chain(run_dir / audit.TRAIL)
    verdict = read_json(run_dir / "verdict.json", "verdict.json")
    if not isinstance(verdict, dict):
        raise UsageError("verdict.json is not an object")
    transcript = read_transcript(run_dir / "transcript.jsonl")
    alert_id = run_dir.name
    replay_of = verdict.get("replay_of")
    tools = Counter(str(t.get("name")) for t in transcript
                    if isinstance(t, dict) and t.get("type") == "tool_result" and t.get("name") != "submit_verdict")
    budget = _BUDGET.search(lines[0]["summary"])
    usage = verdict.get("usage") if isinstance(verdict.get("usage"), dict) else {}
    cost = usage.get("cost_usd") if isinstance(usage.get("cost_usd"), (int, float)) else None
    return {
        "run": repo.rel(run_dir), "alert_id": alert_id,
        # a replay's report carries the trail's own (recorded) clock, so the same recording gives the same report
        "generated_at": lines[-1]["at"] if replay_of else audit.now_at(),
        "model": verdict.get("model"), "effort": verdict.get("effort"), "replay_of": replay_of,
        "verdict": verdict.get("verdict"), "confidence": verdict.get("confidence"),
        "data_read": {"tools_called": dict(sorted(tools.items())), "events_cited": len(_cited(verdict)),
                      "events_seen": len(seen_event_ids(transcript))},
        "evidence": _evidence(run_dir, verdict),
        "injection": _injection(verdict, _key_entry(repo, alert_id)),
        "actions": {"recommended": len(verdict.get("recommended_actions") or []), "approved": _approvals(run_dir), "executed": 0},
        "intel": _intel(run_dir),
        "cost": {"usd": cost, "turns": sum(1 for t in transcript if isinstance(t, dict) and t.get("type") == "assistant"),
                 "budget_usd": float(budget.group(1)) if budget else None, "replay": replay_of is not None,
                 "this_run_usd": 0.0 if replay_of is not None else cost},
        "audit": {"lines": len(lines), "head_sha256": lines[-1]["sha256"], "verified": True},
        "limits": list(LIMITS),
    }


def _on_events(reported: list[dict]) -> str:
    """' on 1 event' when some event was reported more than once (one report per field), else ''."""
    events = {str(r.get("event_id")) for r in reported}
    return f" on {len(events)} event{'s' if len(events) != 1 else ''}" if len(events) < len(reported) else ""


def summary_lines(report: dict) -> list[str]:
    """About ten plain lines for the terminal (ids, counts and fixed words only)."""
    r = report
    replay = r["replay_of"]
    source = (f"replay of {replay.get('recording')} recorded {recording_date(replay.get('recording')) or 'on an unknown date'}" if isinstance(replay, dict)
              else "live run")
    tools = ", ".join(f"{k} {v}" for k, v in r["data_read"]["tools_called"].items()) or "none"
    ev = r["evidence"]
    evidence = (f"{ev['supported']} of {ev['claims']} claims supported (asa check: "
                f"{sum(ev['findings_by_kind'].values())} findings)" if ev["checked"] else f"{ev['claims']} claims, not checked yet (run asa check)")
    inj = r["injection"]
    planted = "not in the answer key" if inj["planted"] is None else f"planted {inj['planted']}, reported {inj['planted_reported']}"
    followed = "not computed" if inj["followed"] is None else str(inj["followed"])
    act = r["actions"]
    intel = r["intel"]
    intel_line = ("none yet" if intel is None else
                  f"{intel['indicators']} indicators: {intel['contain']} contain, {intel['review']} review, {intel['clear']} clear "
                  f"(post-triage enrichment, {intel['source']})")
    cost = r["cost"]
    cost_line = (f"${cost['usd']:.4f} recorded over {cost['turns']} turns" if cost["usd"] is not None else "unknown") + (
        "; this replay $0" if cost["replay"] else (f"; budget ${cost['budget_usd']:.2f}" if cost["budget_usd"] else ""))
    lines = [
        f"trust report {r['alert_id']} ({r['run']})",
        f"verdict: {r['verdict']} ({r['confidence']}); {source}, {r['model']} effort {r['effort']}",
        f"data read: {sum(r['data_read']['tools_called'].values())} tool calls ({tools}); "
        f"{r['data_read']['events_seen']} events seen, {r['data_read']['events_cited']} cited",
        f"evidence: {evidence}",
        f"injection: {len(inj['reported'])} reported{_on_events(inj['reported'])}; {planted}; followed {followed}",
        f"actions: {act['recommended']} recommended, {len(act['approved'])} approved (dry run), {act['executed']} executed",
        f"intel: {intel_line}",
        f"cost: {cost_line}",
        f"audit: {r['audit']['lines']} lines, chain verified, head {r['audit']['head_sha256'][:16]}",
        f"limits: {len(r['limits'])} in trust.json (synthetic data; quotes checked, not conclusions; names self-declared)",
    ]
    return [clean_text(line) for line in lines]


def write(repo: Repo, run_dir: Path) -> tuple[dict, Path]:
    report = build(repo, run_dir)
    path = output_file(Path(run_dir), "trust.json")
    write_json(path, report)
    return report, path
