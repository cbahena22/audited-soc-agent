"""The committed provider fixtures: rebuilt from the seed, synthetic only, and mixed enough to show every verdict."""
import importlib.util
import ipaddress
import json
from pathlib import Path

import pytest

from asa.intel.decide import decide, load_table
from asa.intel.iocs import Ioc, normalise, routable
from asa.intel.layers import Layers
from asa.intel.providers.mock import load_mock_providers

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "data" / "intel" / "fixtures"


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("make_intel_fixtures", ROOT / "tools" / "make_intel_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_files_match_the_seed(tool, capsys):
    assert tool.main(["--check"]) == 0, capsys.readouterr().out


def test_build_is_deterministic(tool):
    assert tool.build() == tool.build()


def test_keys_are_synthetic_documentation_values():
    for fname in ("vt.json", "abuseipdb.json", "otx.json"):
        table = json.loads((FIXTURES / fname).read_text(encoding="utf-8"))
        assert table
        for key in table:
            typ, value = key.split(":", 1)
            ioc = normalise(value, typ)
            assert ioc and ioc.value == value, key
            assert routable(ioc, "demo"), key  # demo profile = RFC 5737 ranges, reserved names, or hashes
            if typ == "ipv4":
                assert any(ipaddress.ip_address(value) in ipaddress.ip_network(n)
                           for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")), key


def test_responses_carry_only_counts(tool):
    raw = (FIXTURES / "vt.json").read_text(encoding="utf-8")
    assert "http" not in raw and "instruction" not in raw.lower()
    for table in tool.build().values():
        for answer in table.values():
            assert isinstance(answer, dict)


def test_every_verdict_appears_in_the_fixtures():
    providers = load_mock_providers(FIXTURES)
    table, layers = load_table(), Layers()
    seen = set()
    keys = set()
    for p in providers:
        keys |= set(p._table)
    for key in keys:
        typ, value = key.split(":", 1)
        ioc = Ioc(typ, value)
        results = [p.lookup(ioc) for p in providers if p.supports(ioc)]
        d = decide(ioc, layers.hits(ioc, results), results, table)
        seen.add((d.bucket, d.reasons[0]))
    assert {("Contain", "PROVIDER_MALICIOUS"), ("Analyst review", "CONFLICTING"), ("Clear", "LOW_SIGNAL"),
            ("Analyst review", "WEAK_SIGNAL")} <= seen


def test_most_indicators_are_clean():
    providers = load_mock_providers(FIXTURES)
    keys = set(providers[0]._table)
    verdicts = []
    for key in keys:
        typ, value = key.split(":", 1)
        ioc = Ioc(typ, value)
        results = [p.lookup(ioc) for p in providers if p.supports(ioc)]
        verdicts.append(decide(ioc, [], results, load_table()).bucket)
    assert verdicts.count("Clear") > len(verdicts) / 2
    assert 1 <= verdicts.count("Contain") <= len(verdicts) / 4
