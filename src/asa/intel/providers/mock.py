"""Fixture providers: answer from committed, synthetic fixtures (one JSON per provider, keyed "type:value"); anything else is no_data. No network."""
from __future__ import annotations

import json
from pathlib import Path

from ..iocs import Ioc
from .base import MAPPERS, SUPPORTED_TYPES, ProviderResult

FILES = {"virustotal": "vt.json", "abuseipdb": "abuseipdb.json", "otx": "otx.json"}
_MAX_FIXTURE_BYTES = 5_000_000


class MockProvider:
    def __init__(self, name: str, table: dict):
        if name not in MAPPERS:
            raise ValueError("unknown provider")
        self.name = name
        self._table = table
        self.calls = 0

    def supports(self, ioc: Ioc) -> bool:
        return ioc.type in SUPPORTED_TYPES[self.name]

    def lookup(self, ioc: Ioc) -> ProviderResult:
        self.calls += 1
        raw = self._table.get(f"{ioc.type}:{ioc.value}")
        if not isinstance(raw, dict):
            return ProviderResult(self.name, {}, "no_data")
        fields = MAPPERS[self.name](raw)
        return ProviderResult(self.name, fields, "ok" if fields else "no_data")


def load_mock_providers(fixtures_dir: Path | None) -> list[MockProvider]:
    """One MockProvider per provider name; a missing fixture file means that provider answers no_data."""
    out = []
    for name, fname in FILES.items():
        table: dict = {}
        if fixtures_dir is not None:
            p = Path(fixtures_dir) / fname
            if p.is_file() and not p.is_symlink() and p.stat().st_size <= _MAX_FIXTURE_BYTES:
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = {}
                if isinstance(data, dict):
                    table = data
        out.append(MockProvider(name, table))
    return out
