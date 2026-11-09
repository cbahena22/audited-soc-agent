"""`asa console build` arguments, the output folder rules and the subcommand wiring."""
import argparse
import json
import os

import pytest

from asa import cli
from asa.common import Repo, UsageError
from asa.console import load
from asa.console.build import write_site
from asa.console.cli import add_parser, out_arg, runs_arg
from console_fixtures import RUN_ID, make_repo, replay


@pytest.fixture
def small(tmp_path):
    repo = Repo(make_repo(tmp_path))
    runs_dir = replay(repo, ["A-007", "A-012"])
    return repo, runs_dir


def parser():
    p = argparse.ArgumentParser(prog="asa")
    add_parser(p.add_subparsers(dest="command", required=True))
    return p


def test_console_build_command_writes_the_site(small, capsys):
    repo, runs_dir = small
    args = parser().parse_args(["console", "build"])
    assert args.handler(args, repo) == 0
    out = capsys.readouterr().out  # the replay wrote real trails; the build verifies them with asa.audit.verify
    assert f"console: 9 pages for 2 alerts of run {RUN_ID}; trails: 2 verified, 0 failed, 0 not checked" in out
    assert "open out/console/index.html" in out
    assert (repo.base / "out" / "console" / "case-A-007.html").is_file()


def test_runs_and_out_arguments_stay_inside_out(small):
    repo, runs_dir = small
    assert runs_arg(repo, None) == runs_dir
    assert runs_arg(repo, f"out/runs/{RUN_ID}") == runs_dir
    assert out_arg(repo, "out/site/v2") == repo.base / "out" / "site" / "v2"
    for bad in ("out/runs/x", f"out/runs/{RUN_ID}/A-007", "data", "../out/runs/" + RUN_ID, "/tmp"):
        with pytest.raises(UsageError):
            runs_arg(repo, bad)
    for bad in ("out", "out/runs/console", "out/ledger", "out/../data", "data/console", "out/a b", "out/" + "x" * 500,
                str(repo.base.parent / "elsewhere"), ""):
        with pytest.raises(UsageError):
            out_arg(repo, bad)


def test_no_run_yet_is_a_usage_error(tmp_path):
    repo = Repo(make_repo(tmp_path))
    with pytest.raises(UsageError, match="no run in out/runs/ yet"):
        runs_arg(repo, None)


def test_refuses_a_folder_that_is_not_an_earlier_build(small):
    repo, _ = small
    out = repo.base / "out" / "console"
    out.mkdir(parents=True)
    (out / "notes.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(UsageError, match="not empty and not an earlier console build"):
        write_site(repo, out, {"index.html": "x"}, RUN_ID)
    assert (out / "notes.txt").read_text(encoding="utf-8") == "mine"


def test_rebuild_replaces_pages_and_keeps_other_files(small):
    repo, _ = small
    out = repo.base / "out" / "console"
    write_site(repo, out, {"index.html": "a", "case-A-001.html": "old"}, RUN_ID)
    (out / "extra.txt").write_text("kept", encoding="utf-8")
    write_site(repo, out, {"index.html": "b"}, RUN_ID)
    assert (out / "index.html").read_text(encoding="utf-8") == "b"
    assert not (out / "case-A-001.html").exists()  # a page of the earlier build that this build does not have
    assert (out / "extra.txt").read_text(encoding="utf-8") == "kept"
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert list(manifest["files"]) == ["index.html"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_links_are_refused(small, tmp_path):
    repo, runs_dir = small
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = repo.base / "out" / "linked"
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted here")
    with pytest.raises(UsageError):
        out_arg(repo, "out/linked")
    with pytest.raises(UsageError, match="not a plain folder"):
        write_site(repo, link, {"index.html": "x"}, RUN_ID)
    # A page name that is a link inside an earlier build is replaced, never written through.
    out = repo.base / "out" / "console"
    write_site(repo, out, {"index.html": "a"}, RUN_ID)
    victim = tmp_path / "victim.txt"
    victim.write_text("safe", encoding="utf-8")
    (out / "index.html").unlink()
    os.symlink(victim, out / "index.html")
    write_site(repo, out, {"index.html": "b"}, RUN_ID)
    assert victim.read_text(encoding="utf-8") == "safe" and not (out / "index.html").is_symlink()
    # A linked verdict.json makes that alert unreadable (shown under "Not shown"), not followed.
    (runs_dir / "A-012" / "verdict.json").unlink()
    os.symlink(runs_dir / "A-007" / "verdict.json", runs_dir / "A-012" / "verdict.json")
    runs, skipped = load.load_run(runs_dir)
    assert [r.alert_id for r in runs] == ["A-007"] and skipped == {"A-012": "verdict.json is a link"}


def test_oversize_and_non_finite_files_become_notes(small):
    repo, runs_dir = small
    run_dir = runs_dir / "A-007"
    (run_dir / "trust.json").write_text('{"cost": {"usd": NaN}}', encoding="utf-8")
    (run_dir / "intel.json").write_bytes(b"{" + b" " * (load.CAPS["intel.json"] + 1) + b"}")
    (run_dir / "audit.jsonl").write_text('{"seq": 1}\nnot json\n[1]\n', encoding="utf-8")
    run = load.load_alert(run_dir)
    assert run.trust is None and run.notes["trust.json"].startswith("not valid JSON")
    assert run.intel is None and run.notes["intel.json"] == f"larger than {load.CAPS['intel.json'] // 1024} KB"
    assert run.trail == [{"seq": 1}, None, None]
    from asa.console.build import render_site

    files, _ = render_site(repo, runs_dir, verify=None)
    assert "trust.json could not be read: not valid JSON" in files["trust-A-007.html"]
    assert "intel.json could not be read: larger than" in files["case-A-007.html"]
    assert files["audit-A-007.html"].count("unreadable line (not a JSON object)") == 2


def test_verdict_of_another_alert_is_skipped(small):
    repo, runs_dir = small
    v = json.loads((runs_dir / "A-012" / "verdict.json").read_text(encoding="utf-8"))
    v["alert_id"] = "A-007"
    (runs_dir / "A-012" / "verdict.json").write_text(json.dumps(v), encoding="utf-8")
    runs, skipped = load.load_run(runs_dir)
    assert skipped == {"A-012": "verdict.json belongs to another alert"}


def _registered(name: str) -> bool:
    for action in cli.build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            return name in action.choices
    return False


@pytest.mark.skipif(not _registered("console"), reason="cli.py patch (console + demo subcommands) not applied yet")
def test_cli_main_runs_console_build(small, monkeypatch, capsys):
    repo, _ = small
    monkeypatch.chdir(repo.base)
    assert _registered("demo")
    assert cli.main(["console", "build", "--out", "out/site"]) == 0
    assert "open out/site/index.html" in capsys.readouterr().out
    assert cli.main(["console", "build", "--out", "../outside"]) == 2
    assert "asa: bad --out" in capsys.readouterr().out
