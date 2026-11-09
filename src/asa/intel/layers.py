"""Local layers: allowlist, denylist, coverage ("known to our EDR"), geo ("outside expected countries")."""
from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from .iocs import Ioc, normalise
from .providers.base import ProviderResult

LAYER_NAMES = ("allowlist", "denylist", "coverage", "geo")
_MAX_ROWS = 100_000


@dataclass
class _Entries:
    exact: set = field(default_factory=set)
    nets: list = field(default_factory=list)
    domains: set = field(default_factory=set)

    def add(self, raw: str) -> None:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            return
        if "/" in raw and "://" not in raw:  # a CIDR range, not a URL
            try:
                self.nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                pass
            return
        for t in ("ipv4", "ipv6", "sha256", "sha1", "md5", "url"):
            n = normalise(raw, t)
            if n:
                self.exact.add(n)
                return
        n = normalise(raw.lstrip("*."), "domain")
        if n:
            self.domains.add(n.value)

    def has(self, ioc: Ioc) -> bool:
        if ioc in self.exact:
            return True
        if ioc.type in ("ipv4", "ipv6"):
            ip = ipaddress.ip_address(ioc.value)
            return any(ip.version == n.version and ip in n for n in self.nets)
        if ioc.type == "domain":
            return any(ioc.value == d or ioc.value.endswith("." + d) for d in self.domains)
        return False


def _read_values(path: Path) -> list[str]:
    if not path.is_file() or path.is_symlink():
        return []
    out: list[str] = []
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        for i, row in enumerate(csv.reader(fh)):
            if i >= _MAX_ROWS:
                break
            if row and row[0].strip().lower() not in ("value", "country"):
                out.append(row[0])
    return out


class Layers:
    def __init__(self, allowlist=(), denylist=(), coverage=(), geo_expected=()):
        self._e = {"allowlist": _Entries(), "denylist": _Entries(), "coverage": _Entries()}
        for name, vals in (("allowlist", allowlist), ("denylist", denylist), ("coverage", coverage)):
            for v in vals:
                self._e[name].add(v)
        self.geo_expected = {c.strip().upper() for c in geo_expected if c.strip()}

    @classmethod
    def from_dir(cls, directory: Path | None) -> "Layers":
        if directory is None:
            return cls()
        d = Path(directory)
        return cls(
            _read_values(d / "allowlist.csv"), _read_values(d / "denylist.csv"),
            _read_values(d / "coverage.csv"), _read_values(d / "geo.csv"),
        )

    def hits(self, ioc: Ioc, results: list[ProviderResult] | None = None) -> list[str]:
        """Names of the layers this IOC hits, in fixed order. geo uses the provider country field."""
        out = [name for name in ("allowlist", "denylist", "coverage") if self._e[name].has(ioc)]
        if self.geo_expected and results:
            countries = {r.fields["country"] for r in results if r.status == "ok" and "country" in r.fields}
            if any(c not in self.geo_expected for c in countries):
                out.append("geo")
        return out
