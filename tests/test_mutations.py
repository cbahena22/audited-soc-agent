"""The regression set must stay exactly as documented: a change either way (a catch lost, a known miss now caught,
a false flag on the clean set) fails here, so the README and the code never drift apart."""
import subprocess
import sys
from pathlib import Path

import pytest

from asa import cli
from asa.common import Repo
from asa.mutate import EXPECTED_CATCHES, KNOWN_MISSES, run_set

SUBFOLDER = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def result():
    return run_set(Repo(SUBFOLDER))


def test_clean_set_covers_every_alert_with_no_false_flags(result):
    assert result["clean_runs"] == 30
    assert result["false_flags"] == {}


@pytest.mark.parametrize("name", [c[0] for c in EXPECTED_CATCHES])
def test_every_expected_catch_is_caught(result, name):
    catch = next(c for c in result["catches"] if c["name"] == name)
    assert catch["caught"], catch
    assert catch["findings"] == [catch["kind"]]  # the mutant raises its own kind and nothing else


@pytest.mark.parametrize("name", [m[0] for m in KNOWN_MISSES])
def test_every_known_miss_is_still_missed(result, name):
    miss = next(m for m in result["misses"] if m["name"] == name)
    assert miss["missed"] and miss["findings"] == [], miss


def test_one_mutant_per_kind_and_four_known_misses(result):
    assert sorted(c["kind"] for c in result["catches"]) == sorted(
        ["missing_event", "not_seen", "quote_mismatch", "uncited_claim", "injection_not_reported", "verdict_differs"])
    assert len(result["misses"]) == 4 and result["demo_alert"] == "A-007" and result["as_expected"]


def test_fixture_repo_set_is_also_clean(repo):
    small = run_set(repo)
    assert small["clean_runs"] == 3 and small["as_expected"]


def test_cli_eval_checker_prints_the_table(monkeypatch, capsys):
    monkeypatch.chdir(SUBFOLDER)
    assert cli.main(["eval", "checker"]) == 0
    out = capsys.readouterr().out
    assert "false flags: 0 of 30" in out
    assert "expected catches (one mutant per kind, on A-007): 6 of 6 caught" in out
    assert "known misses (not built to catch these): 4 of 4 missed, as expected" in out
    assert out.rstrip().endswith("result: as expected")


def test_evals_mutate_script_matches_the_cli(monkeypatch, capsys):
    # The script under evals/ is a thin wrapper; it must print the same table from the repo folder.
    run = subprocess.run([sys.executable, "evals/mutate.py"], cwd=SUBFOLDER, capture_output=True, text=True, timeout=120)
    monkeypatch.chdir(SUBFOLDER)
    cli.main(["eval", "checker"])
    assert run.returncode == 0 and run.stdout.splitlines() == capsys.readouterr().out.splitlines()
