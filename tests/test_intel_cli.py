"""The `intel` subcommand through its own add_parser/run (the staged cli.py patch only registers these two)."""
import argparse
import json

import pytest

from asa.common import UsageError
from asa.intel import cli as intel_cli
from intel_support import real_repo, real_repo_dir, replayed  # noqa: F401


def parse(*argv):
    parser = argparse.ArgumentParser(prog="asa")
    intel_cli.add_parser(parser.add_subparsers(dest="command", required=True))
    return parser.parse_args(["intel", *argv])


def rel(repo, run_dir):
    return repo.rel(run_dir)


def test_prints_defanged_values_and_writes_intel_json(real_repo, replayed, capsys):
    assert intel_cli.run(parse(rel(real_repo, replayed["A-020"])), real_repo) == 0
    out = capsys.readouterr().out
    assert "post-triage enrichment (synthetic provider answers); the verdict did not use it" in out
    assert "203[.]0[.]113[.]150" in out and "203.0.113.150" not in out
    assert "contain" in out and "2 contain, 0 review, 1 clear" in out
    record = json.loads((replayed["A-020"] / "intel.json").read_text(encoding="utf-8"))
    assert record["alert_id"] == "A-020"


def test_defaults(real_repo):
    args = parse("out/runs/x/A-001")
    assert args.fixtures is None and args.max_lookups == 50


def test_run_folder_is_checked_part_by_part(real_repo):
    for bad in ("../outside", "out/runs/20261104T000000Z-mock", "out/runs/nope/A-001", "data/A-001"):
        with pytest.raises(UsageError):
            intel_cli.run(parse(bad), real_repo)


def test_fixtures_folder_must_be_inside_data(real_repo, replayed, tmp_path, capsys):
    run = rel(real_repo, replayed["A-020"])
    outside = tmp_path / "fx"
    outside.mkdir()
    for bad in (str(outside), "evals", "data", "data/intel/fixtures/vt.json", "data/nope", "data/../evals"):
        with pytest.raises(UsageError):
            intel_cli.run(parse(run, "--fixtures", bad), real_repo)
    empty = real_repo.path("data") / "intel" / "empty"
    empty.mkdir()
    assert intel_cli.run(parse(run, "--fixtures", "data/intel/empty"), real_repo) == 0
    assert "0 contain, 3 review, 0 clear" in capsys.readouterr().out  # no fixture answers: every lookup is no_data
    intel_cli.run(parse(run), real_repo)  # leave the shared run folder with the default answers


def test_max_lookups_is_validated(real_repo, replayed):
    with pytest.raises(UsageError):
        intel_cli.run(parse(rel(real_repo, replayed["A-020"]), "--max-lookups", "0"), real_repo)
