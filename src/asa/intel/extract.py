"""Which indicators to look up: typed fields of the events the verdict cites, never text found by pattern.

"Cited" means an event id in a claim's `citations`, a quote's `event_id` or a recommended action's `citations`, limited to ids
that a tool call returned to the agent (the same `seen` rule as the evidence checker). Values come from four typed fields of the
compact event view. A field the agent reported as an injection, or one that holds instruction-shaped text, is skipped, so text
written to steer a reviewer is never looked up or turned into a verdict.
"""
from __future__ import annotations

from ..checker import injected_fields, seen_event_ids
from ..tools import Dataset, compact
from .iocs import Ioc, normalise, routable

# (field name in the compact event view, IOC types to try in order). No file.hash.sha256: the dataset's file events
# carry file.name / file.path only and the tools never show a file hash, so the agent cannot have seen one. Adding it
# means adding it to tools.KIND_FIELDS["file"] too (a test checks every field here is one the tools show).
TYPED_FIELDS = (
    ("source.ip", ("ipv4", "ipv6")),
    ("destination.ip", ("ipv4", "ipv6")),
    ("dns.question.name", ("domain",)),
    ("process.hash.sha256", ("sha256",)),
)


def cited_event_ids(verdict: dict, transcript: list[dict], data: Dataset) -> list[str]:
    """Event ids the verdict cites that exist in data/ and were returned to the agent, sorted."""
    ids: set[str] = set()
    for claim in verdict.get("claims") if isinstance(verdict.get("claims"), list) else []:
        if not isinstance(claim, dict):
            continue
        if isinstance(claim.get("citations"), list):
            ids.update(c for c in claim["citations"] if isinstance(c, str))
        for quote in claim.get("quotes") if isinstance(claim.get("quotes"), list) else []:
            if isinstance(quote, dict) and isinstance(quote.get("event_id"), str):
                ids.add(quote["event_id"])
    for action in verdict.get("recommended_actions") if isinstance(verdict.get("recommended_actions"), list) else []:
        if isinstance(action, dict) and isinstance(action.get("citations"), list):
            ids.update(c for c in action["citations"] if isinstance(c, str))  # model output: a list or dict is skipped
    seen = seen_event_ids(transcript)
    return sorted(i for i in ids if isinstance(i, str) and i in seen and i in data.by_id)


def _reported_fields(verdict: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    reports = verdict.get("injection_reports")
    for report in reports if isinstance(reports, list) else []:
        if isinstance(report, dict) and isinstance(report.get("event_id"), str) and isinstance(report.get("field"), str):
            out.setdefault(report["event_id"], set()).add(report["field"])
    return out


def extract(verdict: dict, transcript: list[dict], data: Dataset) -> tuple[dict[Ioc, list[str]], dict]:
    """({Ioc: [event ids it came from]}, {"not_routable": n, "injection_skipped": n}) for one run."""
    reported = _reported_fields(verdict)
    found: dict[Ioc, set[str]] = {}
    skipped = {"not_routable": 0, "injection_skipped": 0}
    for event_id in cited_event_ids(verdict, transcript, data):
        event = data.by_id[event_id]
        view = compact(event)
        bad = reported.get(event_id, set()) | set(injected_fields(event))
        for field, types in TYPED_FIELDS:
            value = view.get(field)
            if not isinstance(value, str):
                continue
            if field in bad:
                skipped["injection_skipped"] += 1
                continue
            ioc = next((n for n in (normalise(value, t) for t in types) if n), None)
            if ioc is None:
                continue
            if not routable(ioc, "demo"):
                skipped["not_routable"] += 1
                continue
            found.setdefault(ioc, set()).add(event_id)
    return {ioc: sorted(ids) for ioc, ids in sorted(found.items())}, skipped
