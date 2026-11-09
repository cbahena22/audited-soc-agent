"""Decision table: ordered rules, first match wins. Pure function of (hits, provider results, table)."""
from __future__ import annotations

from dataclasses import dataclass

from .config import load_toml
from .iocs import Ioc
from .providers.base import ProviderResult

BUCKETS = ("Contain", "Analyst review", "Clear")
LAYER_WHEN = ("denylist", "allowlist", "coverage")
WHEN = LAYER_WHEN + ("conflicting", "malicious", "geo", "quota", "no_data", "clean")
REASON_CODES = (
    "ALLOWLISTED", "ON_DENYLIST", "IN_COVERAGE", "GEO_OUTSIDE", "PROVIDER_MALICIOUS", "CONFLICTING",
    "NO_DATA", "QUOTA_PENDING", "LOW_SIGNAL", "WEAK_SIGNAL",
)


@dataclass(frozen=True)
class Decision:
    bucket: str
    reasons: list


@dataclass(frozen=True)
class Rule:
    reason: str
    bucket: str
    when: str


@dataclass(frozen=True)
class Table:
    version: str
    thresholds: dict
    rules: tuple
    default: Rule


def _rule(d: dict, when: str | None = None) -> Rule:
    r = Rule(d["reason"], d["bucket"], when or d["when"])
    if r.bucket not in BUCKETS or r.reason not in REASON_CODES or r.when not in WHEN + ("default",):
        raise ValueError("invalid decision table rule")
    return r


def load_table(raw: dict | None = None) -> Table:
    raw = raw if raw is not None else load_toml("decision_table.toml")
    return Table(str(raw["version"]), dict(raw["thresholds"]), tuple(_rule(r) for r in raw["rules"]),
                 _rule(raw["default"], "default"))


def _signals(results: list[ProviderResult], th: dict) -> tuple[bool, bool]:
    """(any provider says malicious, any provider says clean) over results with status ok."""
    bad = clean = False
    for r in results:
        if r.status != "ok":
            continue
        f = r.fields
        if f.get("malicious", 0) >= th["malicious_min"] or f.get("abuse_score", 0) >= th["abuse_score_min"] \
                or f.get("pulse_count", 0) >= th["pulses_min"]:
            bad = True
        elif ("malicious" in f and f["malicious"] <= th["clean_max"] and f.get("suspicious", 0) == 0) \
                or ("abuse_score" in f and f["abuse_score"] <= th["abuse_clean_max"]) \
                or f.get("pulse_count") == 0:
            clean = True
    return bad, clean


def _matches(when: str, hits: list[str], results: list[ProviderResult], th: dict) -> bool:
    if when in LAYER_WHEN:
        return when in hits
    bad, clean = _signals(results, th)
    if when == "conflicting":
        return bad and clean
    if when == "malicious":
        return bad
    if when == "geo":
        return "geo" in hits
    if when == "quota":
        return any(r.status == "quota" for r in results)
    if when == "no_data":
        return not any(r.status == "ok" for r in results)
    if when == "clean":
        return clean and not bad
    return False


def layer_decision(hits: list[str], table: Table) -> Decision | None:
    """The decision when a local-list rule alone settles it (no provider lookup needed), else None.
    Only valid if every rule before the first layer rule is also a layer rule, which load_table's order guarantees
    for the shipped table; custom tables get a lookup (None) in that case."""
    for rule in table.rules:
        if rule.when not in LAYER_WHEN:
            return None
        if rule.when in hits:
            return Decision(rule.bucket, [rule.reason])
    return None


def decide(ioc: Ioc, hits: list[str], results: list[ProviderResult], table: Table) -> Decision:
    for rule in table.rules:
        if _matches(rule.when, hits, results, table.thresholds):
            return Decision(rule.bucket, [rule.reason])
    return Decision(table.default.bucket, [table.default.reason])
