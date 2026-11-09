"""`asa demo` end to end on a copy of the real synthetic dataset and recorded run: $0, no network, a built console."""
import argparse
import json
import socket

import pytest

from asa import audit, demo
from asa.common import Repo, UsageError
from console_fixtures import make_repo
import console_gate


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the demo opened a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_demo_end_to_end(tmp_path, monkeypatch, no_network):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    repo = Repo(make_repo(tmp_path))
    lines = []
    assert demo.run(repo, echo=lines.append) == 0, lines
    text = "\n".join(lines)
    assert "1/6 replay: 30 of 30 alerts from recording live-20261028" in text
    assert '3/6 approvals: A-007 ACT-001, A-021 ACT-002 approved as dry runs by "scripted demo approval"' in text
    assert "2/6 intel (post-triage enrichment, synthetic provider answers): 30 of 30 alerts" in text
    assert "4/6 evidence check: 30 alerts, 0 findings" in text
    assert "5/6 trust reports: 30 of 30 alerts" in text
    assert "skipped" not in text  # intel and trust ran for real
    assert "trails: 30 verified, 0 failed, 0 not checked" in text
    assert "open out/console/index.html" in text
    runs = [p for p in (repo.base / "out" / "runs").iterdir()]
    assert len(runs) == 1
    approvals = (runs[0] / "A-007" / "approvals.jsonl").read_text(encoding="utf-8")
    assert json.loads(approvals)["by"] == "scripted demo approval"
    for alert_dir in runs[0].iterdir():
        for name in ("check.json", "intel.json", "trust.json"):
            assert (alert_dir / name).is_file(), (alert_dir.name, name)
        assert audit.verify(alert_dir) == (True, None, None), alert_dir.name
    trust = json.loads((runs[0] / "A-007" / "trust.json").read_text(encoding="utf-8"))
    assert trust["audit"]["verified"] is True and trust["intel"]["source"] == "fixtures"
    site = repo.base / "out" / "console"
    assert len([p for p in site.iterdir() if p.suffix == ".html"]) == 93
    assert "approved as a dry run by scripted demo approval" in (site / "case-A-007.html").read_text(encoding="utf-8")
    for page in site.iterdir():
        body = page.read_text(encoding="utf-8")
        assert console_gate.hits(body) == [], (page.name, console_gate.hits(body)[:5])
        assert str(tmp_path) not in body
    # one reader-facing recording date (the id's) on every page and in the trust summary; raw stamps stay UTC
    for page in site.iterdir():
        body = page.read_text(encoding="utf-8")
        assert "recorded 2026-10-29" not in body, page.name
        assert page.suffix != ".html" or "recorded 2026-10-28" in body, page.name
    from asa.trust import summary_lines
    assert "replay of live-20261028 recorded 2026-10-28" in "\n".join(summary_lines(trust))
    a008 = json.loads((runs[0] / "A-008" / "trust.json").read_text(encoding="utf-8"))
    assert "injection: 2 reported on 1 event; planted 1, reported 1; followed 0" in summary_lines(a008)
    assert "injection: 1 reported; planted 1, reported 1; followed 0" in summary_lines(trust)
    assert "7 injection reports by the agent on 6 alerts (A-008: 2 reports on 1 event, one per field); 6 of 6 planted" in (
        site / "index.html").read_text(encoding="utf-8")
    assert "Chain verified when this page was built" in (site / "audit-A-007.html").read_text(encoding="utf-8")
    assert "post-triage enrichment (synthetic provider answers)" in (site / "case-A-007.html").read_text(encoding="utf-8")


# (lines, head) of A-007's trail after `asa demo` on the committed recording: the README anchor (any clean clone gets it).
DEMO_A007_ANCHOR = (21, "fbd515d80db1736a5266ac6781de466ee6fe01dfe341adeffe2e46593f619d31")


def test_demo_trail_is_reproducible(tmp_path, monkeypatch, no_network):
    """Two demos on clean copies write the same A-007 trail head: the README can pin it."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    heads = []
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
        repo = Repo(make_repo(tmp_path / name))
        assert demo.run(repo, echo=lambda line: None) == 0
        run = next((repo.base / "out" / "runs").iterdir())
        heads.append(audit.head(run / "A-007"))
    assert heads[0] == heads[1] == DEMO_A007_ANCHOR  # replay 18 lines + intel + approval + check


def test_demo_steps_of_other_parts_run_through_their_subcommands(tmp_path, monkeypatch):
    """Intel and trust run as `asa intel <run>` / `asa trust <run>` when this version has them; else skipped."""
    repo = Repo(make_repo(tmp_path))
    seen = []
    real = demo._parser_has
    real_step = demo._run_step

    def has(argv):
        return argv[0] in ("intel", "trust") or real(argv)

    def step(repo_, argv):
        if argv[0] not in ("intel", "trust"):
            return real_step(repo_, argv)  # the replay itself runs for real
        seen.append(argv[0])
        return (1, "refused: trail does not verify") if argv[0] == "trust" and argv[1].endswith("A-003") else (0, "ok")

    monkeypatch.setattr(demo, "_parser_has", has)
    monkeypatch.setattr(demo, "_run_step", step)
    lines = []
    assert demo.run(repo, echo=lines.append) == 1  # one failed step makes the demo exit 1
    text = "\n".join(lines)
    assert seen.count("intel") == 30 and seen.count("trust") == 30
    assert "2/6 intel (post-triage enrichment, synthetic provider answers): 30 of 30 alerts" in text
    assert "5/6 trust reports: 29 of 30 alerts" in text and "trust failed for A-003 (refused: trail does not verify)" in text


def test_run_step_dispatches_to_handlers_and_captures_output(tmp_path, monkeypatch, capsys):
    repo = Repo(make_repo(tmp_path))
    code, last = demo._run_step(repo, ["eval", "checker"])  # an existing subcommand, through cli.cmd_eval
    assert code == 0 and last
    assert capsys.readouterr().out == ""  # captured, not printed
    assert demo._run_step(repo, ["no-such-command"])[0] == 2
    assert demo._parser_has(["eval", "checker"]) and not demo._parser_has(["no-such-command"])


def test_approvals_step_prints_what_approve_returned(tmp_path):
    """A repeat on the same run says "already approved" (approve() wrote nothing), not "approved" again."""
    from console_fixtures import replay

    repo = Repo(make_repo(tmp_path))
    runs = replay(repo, ["A-007", "A-021"])
    run_dirs = {p.name: p for p in runs.iterdir()}
    first, second = [], []
    demo.approve_scripted(run_dirs, first.append)
    demo.approve_scripted(run_dirs, second.append)
    assert any("ACT-001 approved (dry run, not sent) by scripted demo approval" in x for x in first), first
    assert any("ACT-001 is already approved (dry run, not sent)" in x for x in second), second
    assert not any("A-007 ACT-001, A-021 ACT-002 approved" in x for x in second), second
    assert len((runs / "A-007" / "approvals.jsonl").read_text(encoding="utf-8").splitlines()) == 1


def test_bad_out_is_refused_before_any_work(tmp_path):
    repo = Repo(make_repo(tmp_path))
    with pytest.raises(UsageError):
        demo.run(repo, "out/runs/x", echo=lambda line: None)
    assert not (repo.base / "out" / "runs").exists()


def test_demo_parser():
    p = argparse.ArgumentParser(prog="asa")
    demo.add_parser(p.add_subparsers(dest="command", required=True))
    args = p.parse_args(["demo"])
    assert args.out == "out/console" and args.handler is demo.cmd_demo
