"""Enrich one run with threat-intel answers from synthetic fixtures. Runs after triage: the verdict never used any of it.

`enrich(...)` reads verdict.json and transcript.jsonl, looks up the indicators the verdict cites in the fixture providers, applies
the decision table and writes intel.json. Fixture mode only: nothing here opens a socket or reads a key.
"""
from __future__ import annotations

from pathlib import Path

from ..audit import note_file
from ..checker import read_transcript
from ..common import Repo, UsageError, output_file, read_json, write_json
from ..tools import Dataset
from .decide import decide, layer_decision, load_table
from .extract import extract
from .layers import Layers
from .providers.mock import load_mock_providers

LABEL = "post-triage enrichment (synthetic provider answers)"
SOURCE = "fixtures"
FETCHED_AT = "2026-11-04T00:00:00Z"  # fixed on purpose: the same inputs give the same bytes; the answers are synthetic
OWN_TENANT_ALLOWLIST = ("*.corp.example",)  # the fictional client's own names: never looked up
SHORT = {"virustotal": "vt", "abuseipdb": "abuseipdb", "otx": "otx"}
VERDICT = {"Contain": "contain", "Analyst review": "review", "Clear": "clear"}
DEFAULT_MAX_LOOKUPS = 50
MAX_LOOKUPS_LIMIT = 1000


def _provider_record(result) -> dict:
    return {"status": result.status, "fields": dict(result.fields), "fetched_at": FETCHED_AT}


def enrich(repo: Repo, run_dir: Path, fixtures_dir: Path | None = None, max_lookups: int = DEFAULT_MAX_LOOKUPS,
           data: Dataset | None = None) -> dict:
    """Build the intel record for one run folder and write intel.json beside verdict.json."""
    if not isinstance(max_lookups, int) or isinstance(max_lookups, bool) or not 1 <= max_lookups <= MAX_LOOKUPS_LIMIT:
        raise UsageError(f"--max-lookups must be a whole number from 1 to {MAX_LOOKUPS_LIMIT}")
    alert_id = run_dir.name
    verdict = read_json(run_dir / "verdict.json", "verdict.json")
    if not isinstance(verdict, dict) or verdict.get("alert_id") != alert_id:
        raise UsageError("verdict.json does not belong to this run folder's alert")
    transcript = read_transcript(run_dir / "transcript.jsonl")
    data = data or Dataset(repo)
    indicators, skipped = extract(verdict, transcript, data)
    fixtures = fixtures_dir if fixtures_dir is not None else repo.path("data", "intel", "fixtures")
    providers = load_mock_providers(fixtures)
    layers = Layers(allowlist=OWN_TENANT_ALLOWLIST)
    table = load_table()
    skipped["lookup_cap"] = 0
    lookups = 0
    out = []
    for ioc, event_ids in indicators.items():
        hits = layers.hits(ioc)
        decision = layer_decision(hits, table)
        recorded: dict = {}
        if decision is None:
            usable = [p for p in providers if p.supports(ioc)]
            if lookups + len(usable) > max_lookups:
                skipped["lookup_cap"] += 1
                continue
            lookups += len(usable)
            results = [p.lookup(ioc) for p in usable]
            decision = decide(ioc, layers.hits(ioc, results), results, table)
            recorded = {SHORT[r.provider]: _provider_record(r) for r in results}
        out.append({"type": ioc.type, "value": ioc.value, "from_event_ids": event_ids,
                    "verdict": VERDICT[decision.bucket], "rule": decision.reasons[0], "providers": recorded})
    record = {"run": repo.rel(run_dir), "alert_id": alert_id, "source": SOURCE, "label": LABEL,
              "used_in_verdict": False, "skipped": skipped, "indicators": out}
    # intel.json and its trail line under one lock; a run without a trail gets the file only. A trail that does not
    # verify refuses before the file is written; a failed append after it says "intel.json written; trail append failed".
    s = summary(record)
    note_file(run_dir, "intel", record,
              f"{s['indicators']} indicators from cited events: {s['contain']} contain, {s['review']} review, "
              f"{s['clear']} clear ({LABEL})",
              write=lambda: write_json(output_file(run_dir, "intel.json"), record))
    return record


def summary(record: dict) -> dict:
    """The counts the trust report shows: {indicators, contain, review, clear, source}."""
    rows = record.get("indicators") if isinstance(record.get("indicators"), list) else []
    counts = {name: sum(1 for r in rows if isinstance(r, dict) and r.get("verdict") == name)
              for name in ("contain", "review", "clear")}
    return {"indicators": len(rows), **counts, "source": record.get("source")}


__all__ = ["enrich", "summary", "LABEL"]
