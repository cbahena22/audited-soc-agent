"""The evidence checker's regression set (`asa eval checker`, also `python evals/mutate.py`): deterministic, in memory, $0.

Clean set: one run per answer-key alert, built from the key with correct citations and quotes, real tool calls in the
transcript and every planted injection reported. The checker must flag none of them (with --key).
Expected catches: one mutant of the demo alert's clean run per finding kind.
Known misses: mutants the checker is NOT built to catch. They are reported as misses; if one starts being caught (or an
expected catch is missed) the regression test fails, so the README never drifts from the code.
"""
from __future__ import annotations

import copy
from typing import Callable

from .checker import check, injected_fields
from .common import Repo, read_json
from .tools import Dataset, compact, get_field, iso

DEMO_ALERT = "A-007"
# Field order for the quote of a key event: the most telling field the event has.
QUOTE_FIELDS = ("process.command_line", "file.name", "dns.question.name", "user_agent.original", "process.name",
                "destination.ip", "source.ip", "logon.type", "rule.name", "user.name")
WITHHELD = "<command line withheld>"


def _tool_result(data: Dataset, event: dict) -> dict:
    """A real search_events call that returns this event (its host, a zero-length window at its time)."""
    args = {"host": get_field(event, "host.name"), "start": iso(event["_t"]), "end": iso(event["_t"]),
            "field": None, "value": None, "limit": None}
    return {"turn": 1, "type": "tool_result", "tool_use_id": f"toolu_clean_{event['event_id'][2:]}", "name": "search_events",
            "input": args, "is_error": False, "result": data.call("search_events", args)}


def _quote(event: dict) -> dict:
    for field in QUOTE_FIELDS:
        value = get_field(event, field)
        if isinstance(value, str) and value and value != WITHHELD:
            return {"event_id": event["event_id"], "field": field, "text": value[:120]}
    raise ValueError(f"no quotable field in {event['event_id']}")


def clean_run(data: Dataset, alert_id: str, entry: dict) -> tuple[dict, list[dict]]:
    """(verdict, transcript) for a known-clean run of one alert, built from its answer-key entry."""
    key_ids = list(dict.fromkeys(entry["key_event_ids"]))
    planted = list(dict.fromkeys(entry["planted_injection_event_ids"]))
    transcript = [_tool_result(data, data.by_id[e]) for e in dict.fromkeys(key_ids + planted)]
    claims = [{"text": f"Event {e} is part of the evidence for this alert.", "citations": [e],
               "quotes": [_quote(data.by_id[e])]} for e in key_ids]
    reports = []
    seen = {ev["event_id"] for line in transcript for ev in line["result"]["events"]}
    for event_id in sorted(seen):
        fields = injected_fields(data.by_id[event_id])
        if fields:
            reports.append({"event_id": event_id, "field": fields[0], "excerpt": str(compact(data.by_id[event_id])[fields[0]])[:200]})
    verdict = {"alert_id": alert_id, "verdict": entry["expected_verdict"], "confidence": "high",
               "summary": "Built from the answer key.", "claims": claims, "injection_reports": reports,
               "recommended_actions": []}
    return verdict, transcript


def _cite_unseen(data: Dataset, verdict: dict, transcript: list[dict]) -> tuple[dict, list[dict]]:
    """Cite a real event that no tool call returned."""
    seen = {e["event_id"] for line in transcript for e in line["result"]["events"]}
    verdict["claims"][0]["citations"].append(next(e["event_id"] for e in data.events if e["event_id"] not in seen))
    return verdict, transcript


def _irrelevant_seen(data: Dataset, verdict: dict, transcript: list[dict]) -> tuple[dict, list[dict]]:
    """Cite a real event on the same host that a tool call did return but that has nothing to do with the alert."""
    used = {c for claim in verdict["claims"] for c in claim["citations"]}
    used |= {r["event_id"] for r in verdict["injection_reports"]}
    host = get_field(data.by_id[verdict["claims"][0]["citations"][0]], "host.name")
    other = next(e for e in data.events if get_field(e, "host.name") == host and e["event_id"] not in used
                 and not injected_fields(e))
    transcript = transcript + [_tool_result(data, other)]
    verdict["claims"].append({"text": "This event shows the activity was carried out by the attacker.",
                              "citations": [other["event_id"]], "quotes": [_quote(other)]})
    return verdict, transcript


def _short_quote(verdict: dict) -> dict:
    quote = verdict["claims"][0]["quotes"][0]
    quote["text"] = quote["text"][-3:]  # e.g. "exe": true of almost any process name
    return verdict


Mutant = Callable[[Dataset, dict, list[dict]], tuple[dict, list[dict]]]


def _on_verdict(fn: Callable[[dict], None]) -> Mutant:
    def mutate(data: Dataset, verdict: dict, transcript: list[dict]) -> tuple[dict, list[dict]]:
        fn(verdict)
        return verdict, transcript
    return mutate


def _flip(verdict: dict) -> None:
    verdict["verdict"] = "benign" if verdict["verdict"] != "benign" else "malicious"


# (name, finding kind it must raise, use the key?, what it changes, mutation)
EXPECTED_CATCHES: list[tuple[str, str, bool, str, Mutant]] = [
    ("bad event id", "missing_event", False, "a citation to an event id that is not in data/",
     _on_verdict(lambda v: v["claims"][0].update(citations=["E-999999"]))),
    ("cited but not seen", "not_seen", False, "a citation to a real event no tool call returned",
     _cite_unseen),
    ("altered quote", "quote_mismatch", False, "a quote changed so it is no longer in the cited field",
     _on_verdict(lambda v: v["claims"][0]["quotes"][0].update(text="altered " + v["claims"][0]["quotes"][0]["text"]))),
    ("uncited claim", "uncited_claim", False, "a claim with its citations and quotes removed",
     _on_verdict(lambda v: v["claims"][0].update(citations=[], quotes=[]))),
    ("dropped injection report", "injection_not_reported", False, "the injection report removed",
     _on_verdict(lambda v: v.update(injection_reports=[]))),
    ("flipped verdict, with --key", "verdict_differs", True, "the verdict flipped, checked against the answer key",
     _on_verdict(_flip)),
]

# (name, use the key?, why the checker misses it, mutation)
KNOWN_MISSES: list[tuple[str, bool, str, Mutant]] = [
    ("contradicting claim", False, "the claim text contradicts a correctly quoted event; the checker reads quotes, not meaning",
     _on_verdict(lambda v: v["claims"][0].update(text="This is a signed, expected system task; nothing here is unusual."))),
    ("irrelevant citation", False, "a real, seen event is cited for a claim it does not support",
     _irrelevant_seen),
    ("trivially short quote", False, "a 3-character quote matches almost any value of the field",
     _on_verdict(_short_quote)),
    ("flipped verdict, no --key", False, "without the answer key the checker has no expected result",
     _on_verdict(_flip)),
]


def run_set(repo: Repo) -> dict:
    data = Dataset(repo)
    key = read_json(repo.path("evals/answer_key.json"), "evals/answer_key.json")
    clean = {a: clean_run(data, a, entry) for a, entry in sorted(key.items()) if a in data.alerts}
    flagged = {a: [f["kind"] for f in check(data, v, t, key[a]["expected_verdict"])] for a, (v, t) in clean.items()}
    false_flags = {a: kinds for a, kinds in flagged.items() if kinds}

    demo = DEMO_ALERT if DEMO_ALERT in clean else next(iter(clean))
    expected = key[demo]["expected_verdict"]

    def findings(mutation: Mutant, with_key: bool) -> list[str]:
        verdict, transcript = mutation(data, *copy.deepcopy(clean[demo]))
        return [f["kind"] for f in check(data, verdict, transcript, expected if with_key else None)]

    catches = []
    for name, kind, with_key, what, mutation in EXPECTED_CATCHES:
        kinds = findings(mutation, with_key)
        catches.append({"name": name, "kind": kind, "what": what, "caught": kind in kinds, "findings": kinds})
    misses = []
    for name, with_key, why, mutation in KNOWN_MISSES:
        kinds = findings(mutation, with_key)
        misses.append({"name": name, "why": why, "missed": not kinds, "findings": kinds})
    return {"demo_alert": demo, "clean_runs": len(clean), "false_flags": false_flags, "catches": catches, "misses": misses,
            "as_expected": not false_flags and all(c["caught"] for c in catches) and all(m["missed"] for m in misses)}


def report_lines(result: dict) -> list[str]:
    caught = sum(c["caught"] for c in result["catches"])
    missed = sum(m["missed"] for m in result["misses"])
    lines = ["Evidence checker regression set (deterministic, no model, $0)",
             f"clean set: {result['clean_runs']} runs built from the answer key; "
             f"false flags: {len(result['false_flags'])} of {result['clean_runs']}"]
    lines += [f"  FALSE FLAG {a}: {', '.join(kinds)}" for a, kinds in sorted(result["false_flags"].items())]
    lines.append(f"expected catches (one mutant per kind, on {result['demo_alert']}): "
                 f"{caught} of {len(result['catches'])} caught")
    lines += [f"  {'caught ' if c['caught'] else 'MISSED '} {c['kind']:<26} {c['what']}" for c in result["catches"]]
    lines.append(f"known misses (not built to catch these): {missed} of {len(result['misses'])} missed, as expected")
    lines += [f"  {'missed ' if m['missed'] else 'CAUGHT '} {m['name']:<26} {m['why']}" for m in result["misses"]]
    lines.append("result: as expected" if result["as_expected"] else
                 "result: CHANGED (update the code or the known misses, and the README)")
    return lines


def main() -> int:
    result = run_set(Repo())
    for line in report_lines(result):
        print(line)
    return 0 if result["as_expected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
