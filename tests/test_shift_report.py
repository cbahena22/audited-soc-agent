import json

import pytest

from asa import cli
from asa.agent import investigate
from asa.llm import ReplayClient
from fakes import FIXTURE_ALERTS, fixture_turns

RUN1, RUN2 = "20261027T010000Z-mock", "20261027T090000Z-mock"


@pytest.fixture
def runs(repo, repo_dir, monkeypatch):
    """Two run folders: all three fixture alerts at 01:00, A-012 again at 09:00 with a changed verdict."""
    for alert_id in FIXTURE_ALERTS:
        investigate(alert_id, ReplayClient(fixture_turns(alert_id), "fixture", require_live=False), repo, run_id=RUN1)
    run_dir, _ = investigate("A-012", ReplayClient(fixture_turns("A-012"), "fixture", require_live=False), repo, run_id=RUN2)
    verdict = json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))
    verdict.update(verdict="needs_human", summary="Second look: \x1b[31m## [click](http://198.51.100.9/x) <b>owner</b> unclear")
    verdict["recommended_actions"] = [{"id": "ACT-001", "action": "open_ticket", "target": "WS-05`\n## injected",
                                       "reason": "Ask the client who owns the script.", "citations": ["E-000201"]}]
    (run_dir / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
    (repo_dir / "out" / "runs" / RUN2 / "A-021").mkdir()  # a run that stopped before its verdict is skipped
    monkeypatch.chdir(repo_dir)
    assert cli.main(["approve", "ACT-001", "--run", f"out/runs/{RUN1}/A-007", "--as", "Night Lead"]) == 0
    return repo_dir


def report(capsys, since="2026-10-27T00:00:00Z"):
    capsys.readouterr()
    assert cli.main(["shift-report", "--since", since]) == 0
    return capsys.readouterr().out


def section(out, title):
    body = out.split(f"## {title}\n", 1)[1]
    return [line for line in body.split("\n## ", 1)[0].splitlines() if line.strip()]


def test_open_changed_waiting(runs, capsys):
    out = report(capsys)
    assert out.startswith("# Shift report since 2026-10-27T00:00:00Z")
    assert "4 alert runs in 2 run folder(s), 3 alerts." in out
    opened = section(out, "Open (needs a person)")
    assert [line.split(" (run")[0] for line in opened] == ["- A-012", "- A-021"]
    assert section(out, "Changed between runs") == [f"- A-012: benign ({RUN1}) -> needs_human ({RUN2})"]
    waiting = section(out, "Waiting for approval")
    assert [" ".join(line.split()[1:3]) for line in waiting] == ["A-007 ACT-002", "A-012 ACT-001", "A-021 ACT-001"]
    assert not any("A-007 ACT-001" in line for line in waiting)  # approved (dry run)


def test_model_text_cannot_add_markdown_or_terminal_codes(runs, capsys):
    out = report(capsys)
    assert "\x1b" not in out
    assert out.count("\n## ") == 3  # only the three section headings, nothing injected
    assert "\\[click\\]\\(http" in out and "\\<b\\>owner\\</b\\>" in out
    assert "WS-05\\` \\#\\# injected" in out


def test_since_filters_runs(runs, capsys):
    out = report(capsys, "2026-10-27T05:00:00Z")
    assert "1 alert runs in 1 run folder(s), 1 alerts." in out
    assert section(out, "Changed between runs") == ["None."]


def test_empty_and_bad_since(repo_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo_dir)
    out = report(capsys)
    assert "0 alert runs" in out and section(out, "Open (needs a person)") == ["None."]
    for bad in ("yesterday", "2026-13-01", "9" * 50):
        assert cli.main(["shift-report", "--since", bad]) == 2
        assert capsys.readouterr().out.startswith("asa: bad --since")


def test_empty_since_and_a_bogus_run_folder(runs, capsys):
    assert cli.main(["shift-report", "--since", ""]) == 2
    (runs / "out" / "runs" / "99999999T999999Z-mock" / "A-007").mkdir(parents=True)
    out = report(capsys)
    assert "4 alert runs in 2 run folder(s)" in out
