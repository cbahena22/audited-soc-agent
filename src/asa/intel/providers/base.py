"""Provider contract, the fixed verdict-field subset, and mappers from public-API response shapes."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from ..iocs import Ioc

STATUSES = ("ok", "no_data", "quota", "error")
# The only fields that ever leave a provider response: they feed the decision table, the notes and the cache.
ALLOWED_FIELDS = {
    "malicious": int, "suspicious": int, "harmless": int,
    "abuse_score": int, "total_reports": int, "pulse_count": int,
    "country": str,
}
_COUNTRY = re.compile(r"^[A-Z]{2}$")


def clean_fields(raw: dict) -> dict:
    """Keep only allowed fields with the right type and a sane range. Free text never passes (no injection carrier)."""
    out: dict = {}
    for k, typ in ALLOWED_FIELDS.items():
        v = raw.get(k)
        if v is None or isinstance(v, bool):
            continue
        if typ is int and isinstance(v, int) and 0 <= v <= 10_000_000:
            out[k] = v
        elif typ is str and isinstance(v, str) and _COUNTRY.match(v):
            out[k] = v
    return out


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    fields: dict = field(default_factory=dict)
    status: str = "ok"

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError("bad provider status")


class Provider(Protocol):
    name: str

    def supports(self, ioc: Ioc) -> bool: ...
    def lookup(self, ioc: Ioc) -> ProviderResult: ...


def _get(d, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def map_vt(raw: dict) -> dict:
    stats = _get(raw, "data", "attributes", "last_analysis_stats")
    if not isinstance(stats, dict):
        stats = {}  # malformed fixture / response: no counts, not a traceback
    return clean_fields({
        "malicious": stats.get("malicious"), "suspicious": stats.get("suspicious"), "harmless": stats.get("harmless"),
        "country": _get(raw, "data", "attributes", "country"),
    })


def map_abuseipdb(raw: dict) -> dict:
    return clean_fields({
        "abuse_score": _get(raw, "data", "abuseConfidenceScore"),
        "total_reports": _get(raw, "data", "totalReports"),
        "country": _get(raw, "data", "countryCode"),
    })


def map_otx(raw: dict) -> dict:
    return clean_fields({
        "pulse_count": _get(raw, "pulse_info", "count"),
        "country": raw.get("country_code") if isinstance(raw, dict) else None,
    })


MAPPERS = {"virustotal": map_vt, "abuseipdb": map_abuseipdb, "otx": map_otx}
SUPPORTED_TYPES = {
    "virustotal": {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"},
    "abuseipdb": {"ipv4", "ipv6"},
    "otx": {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"},
}
