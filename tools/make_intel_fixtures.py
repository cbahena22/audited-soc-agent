"""Build the synthetic threat-intel provider answers in data/intel/fixtures/ (deterministic, no network).

    python tools/make_intel_fixtures.py          # rewrite the three files
    python tools/make_intel_fixtures.py --check  # exit 1 when the files on disk differ from what the seed builds

One JSON file per provider, keyed "type:value", in each provider's public-API response shape (the shape the field mappers in
src/asa/intel/providers/base.py read). Indicators come from the typed fields of the events the recorded verdicts cite plus the
answer key's key events. A few are pinned as malicious or conflicting; the rest are mostly clean, with some answered "no data".
Every value is synthetic (RFC 5737 addresses, reserved names): these are not real provider answers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from asa.intel.extract import TYPED_FIELDS  # noqa: E402
from asa.intel.iocs import normalise, routable  # noqa: E402
from asa.tools import compact  # noqa: E402

SEED = "asa-intel-fixtures-1"
OUT = ROOT / "data" / "intel" / "fixtures"
FILES = {"vt": "vt.json", "abuseipdb": "abuseipdb.json", "otx": "otx.json"}
# Pinned answers, so the demo has a malicious and a conflicting indicator that a reader can find by name.
PINNED = {
    "ipv4:203.0.113.150": "malicious", "domain:assist.vendor-support.example": "malicious",
    "ipv4:203.0.113.77": "malicious", "ipv4:203.0.113.40": "malicious",
    "sha256:" + "7c" * 32: "malicious",  # the encoded PowerShell of A-007
    "ipv4:198.51.100.140": "conflicting", "domain:vault.offsite-backup.example": "conflicting",
}


def _n(key: str, salt: str, low: int, high: int) -> int:
    h = int(hashlib.sha256(f"{SEED}|{salt}|{key}".encode()).hexdigest()[:8], 16)
    return low + h % (high - low + 1)


def kind_of(key: str) -> str:
    if key in PINNED:
        return PINNED[key]
    slot = _n(key, "kind", 0, 19)
    return "absent" if slot < 3 else "weak" if slot < 5 else "conflicting" if slot == 5 else "clean"


def answers(key: str, kind: str) -> dict[str, dict]:
    """provider -> raw response for one indicator (a provider that does not cover the type is left out)."""
    typ = key.split(":", 1)[0]
    ip = typ in ("ipv4", "ipv6")
    harmless = _n(key, "harmless", 55, 80)
    vt_stats = {"clean": (0, 0), "malicious": (_n(key, "vt", 8, 15), 2), "conflicting": (_n(key, "vt", 4, 7), 1),
                "weak": (1, 1)}[kind]
    out = {"vt": {"data": {"attributes": {"last_analysis_stats": {
        "harmless": harmless, "malicious": vt_stats[0], "suspicious": vt_stats[1]}}}}}
    pulses = {"clean": 0, "malicious": _n(key, "otx", 6, 12), "conflicting": 0, "weak": 1}[kind]
    out["otx"] = {"pulse_info": {"count": pulses}}
    if ip:
        score = {"clean": 0, "malicious": _n(key, "abuse", 80, 100), "conflicting": _n(key, "abuse", 0, 5),
                 "weak": _n(key, "abuse", 20, 40)}[kind]
        out["abuseipdb"] = {"data": {"abuseConfidenceScore": score, "totalReports": 0 if score < 10 else score // 4}}
    return out


def indicator_keys() -> list[str]:
    """type:value for every routable typed-field value in the cited and key events."""
    events = {}
    for line in (ROOT / "data" / "events.ndjson").read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = json.loads(line)
            events[e["event_id"]] = e
    ids: set[str] = set()
    key = json.loads((ROOT / "evals" / "answer_key.json").read_text(encoding="utf-8"))
    for entry in key.values():
        ids.update(entry["key_event_ids"])
    for path in sorted((ROOT / "evals" / "recorded").glob("live-*/A-*/turns.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            for block in json.loads(line)["response"]["content"]:
                if block.get("name") == "submit_verdict":
                    for claim in block["input"]["claims"]:
                        ids.update(claim.get("citations", []))
                        ids.update(q["event_id"] for q in claim.get("quotes", []))
                    for action in block["input"]["recommended_actions"]:
                        ids.update(action.get("citations", []))
    keys: set[str] = set()
    for event_id in ids & events.keys():
        view = compact(events[event_id])
        for field, types in TYPED_FIELDS:
            value = view.get(field)
            if isinstance(value, str):
                ioc = next((n for n in (normalise(value, t) for t in types) if n), None)
                if ioc and routable(ioc, "demo") and not ioc.value.endswith(".corp.example"):
                    keys.add(f"{ioc.type}:{ioc.value}")
    return sorted(keys)


def build() -> dict[str, dict]:
    tables: dict[str, dict] = {name: {} for name in FILES}
    for key in indicator_keys():
        kind = kind_of(key)
        if kind == "absent":
            continue
        for provider, raw in answers(key, kind).items():
            tables[provider][key] = raw
    return tables


def render(table: dict) -> str:
    return json.dumps(table, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare with the files on disk, write nothing")
    args = parser.parse_args(argv)
    tables = build()
    stale = []
    for name, fname in FILES.items():
        text, path = render(tables[name]), OUT / fname
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(fname)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {path.relative_to(ROOT).as_posix()}: {len(tables[name])} indicators")
    if stale:
        print("out of date: " + ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
