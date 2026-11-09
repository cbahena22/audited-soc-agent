import json
import os
import shutil
import socket

import pytest

from asa import cli
from asa.agent import MAX_TURNS, investigate
from asa.llm import ReplayClient, ReplayMismatch
from asa.prompt import NUDGE
from fakes import FIXTURES, ScriptedClient, complete_marker, fixture_turns, response

VERDICT_KEYS = {"alert_id", "verdict", "confidence", "summary", "claims", "injection_reports", "recommended_actions",
                "stop_note", "model", "effort", "replay_of", "usage"}


def replay(alert_id):
    return ReplayClient(fixture_turns(alert_id), "fixture", require_live=False)


def install_live_recording(repo_dir, name="live-20261027", alert_id="A-007", source="live"):
    dest = repo_dir / "evals" / "recorded" / name / alert_id / "turns.jsonl"
    dest.parent.mkdir(parents=True)
    turns = fixture_turns(alert_id)
    dest.write_text("".join(json.dumps({**t, "source": source}) + "\n" for t in turns), encoding="utf-8")
    (dest.parent / "complete.json").write_text(complete_marker(alert_id, turns), encoding="utf-8")


def test_fixture_replays_are_current(tmp_path):
    from build_recorded import build  # tests/fixtures is on the path via conftest below

    build(tmp_path)
    for alert_dir in (FIXTURES / "recorded" / "fixture").iterdir():
        assert (tmp_path / alert_dir.name / "turns.jsonl").read_bytes() == (alert_dir / "turns.jsonl").read_bytes()


def test_a007_fixture_gives_valid_verdict(repo, repo_dir):
    run_dir, verdict = investigate("A-007", replay("A-007"), repo, run_id="20261027T000000Z-mock")
    on_disk = json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))
    assert on_disk == verdict and set(verdict) == VERDICT_KEYS
    assert verdict["verdict"] == "malicious" and verdict["stop_note"] is None
    assert [r["event_id"] for r in verdict["injection_reports"]] == ["E-000102"]
    assert verdict["replay_of"] == {"recording": "fixture", "model": "claude-sonnet-5-5", "recorded_at": "2026-10-27T00:00:00Z"}
    assert verdict["usage"]["cost_usd"] > 0 and verdict["usage"]["input_tokens"] == 18600
    lines = [json.loads(x) for x in (run_dir / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    seen = {e["event_id"] for x in lines if x["type"] == "tool_result" for e in x["result"].get("events", [])}
    assert "E-000102" in seen and (run_dir / "case.html").is_file()
    assert run_dir == repo_dir / "out" / "runs" / "20261027T000000Z-mock" / "A-007"


@pytest.mark.parametrize("alert_id,expected", [("A-012", "benign"), ("A-021", "needs_human")])
def test_other_fixtures(repo, alert_id, expected):
    _, verdict = investigate(alert_id, replay(alert_id), repo, run_id="20261027T000000Z-mock")
    assert verdict["verdict"] == expected and verdict["stop_note"] is None


def test_replay_hash_mismatch_is_a_clear_error(repo_dir):
    from asa.common import Repo

    path = repo_dir / "data" / "events.ndjson"
    path.write_text(path.read_text(encoding="utf-8").replace("intranet.corp.example", "files.corp.example"), encoding="utf-8")
    with pytest.raises(ReplayMismatch, match="result_sha256 differs"):
        investigate("A-007", replay("A-007"), Repo(repo_dir), run_id="20261027T000000Z-mock")


def test_replay_of_a_different_tool_call_is_refused(repo):
    turns = fixture_turns("A-007")
    turns[0]["response"]["content"][1]["input"]["process_entity_id"] = "P-0a0000000102"
    with pytest.raises(ReplayMismatch, match="input differs"):
        investigate("A-007", ReplayClient(turns, "fixture", require_live=False), repo, run_id="20261027T000000Z-mock")


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network used in mock mode")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_cli_mock_replays_without_network_or_key(repo_dir, monkeypatch, capsys, no_network):
    install_live_recording(repo_dir)
    monkeypatch.chdir(repo_dir)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "replay of recorded run live-20261027, claude-sonnet-5-5, 2026-10-27"
    assert "verdict: malicious (high)" in out and "case page: out/runs/" in out
    assert str(repo_dir) not in out
    html = next((repo_dir / "out" / "runs").glob("*-mock/A-007/case.html")).read_text(encoding="utf-8")
    assert "replay of recorded run live-20261027, claude-sonnet-5-5, 2026-10-27" in html


def test_cli_mock_without_live_recording_exits_2(repo_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo_dir)
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 2
    assert "no recorded live run yet" in capsys.readouterr().out
    (repo_dir / "evals" / "recorded" / "fixture").mkdir(parents=True)  # a non-live folder does not count
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 2


def test_cli_mock_refuses_a_fixture_source(repo_dir, monkeypatch, capsys):
    install_live_recording(repo_dir, source="hand-written fixture")
    monkeypatch.chdir(repo_dir)
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 2
    assert "not a live recording" in capsys.readouterr().out


def test_cli_refuses_outside_a_repo(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 2
    assert capsys.readouterr().out.strip() == "asa: run asa from the repo folder (./data/alerts.json not found)"


def test_cli_bad_alert_id(repo_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo_dir)
    assert cli.main(["investigate", "--alert", "../A-007", "--mock"]) == 2


@pytest.mark.parametrize("stop,note", [("refusal", "refused"), ("max_tokens", "out of tokens"), ("end_turn", "no verdict")])
def test_stop_reason_nudges_once_then_needs_human(repo, stop, note):
    content = [{"type": "text", "text": "Thinking about it."}]
    client = ScriptedClient([response(content, stop), response(content, stop)])
    _, verdict = investigate("A-007", client, repo, run_id="20261027T000000Z-live")
    assert len(client.requests) == 2
    assert client.requests[1]["messages"][-1] == {"role": "user", "content": NUDGE}
    assert sum(1 for m in client.requests[1]["messages"] if m.get("content") == NUDGE) == 1
    assert verdict["verdict"] == "needs_human" and verdict["stop_note"] == note and verdict["claims"] == []


def test_nudge_then_verdict(repo):
    submit = fixture_turns("A-021")[-1]["response"]
    client = ScriptedClient([response([{"type": "text", "text": "Done."}], "end_turn"), submit])
    _, verdict = investigate("A-021", client, repo, run_id="20261027T000000Z-live")
    assert verdict["verdict"] == "needs_human" and verdict["stop_note"] is None


def test_turn_limit(repo):
    call = {"type": "tool_use", "id": "toolu_1", "name": "get_alert", "input": {"alert_id": "A-007"}}
    client = ScriptedClient([response([call], "tool_use")] * MAX_TURNS)
    _, verdict = investigate("A-007", client, repo, run_id="20261027T000000Z-live")
    assert len(client.requests) == MAX_TURNS and verdict["stop_note"] == "turn limit"


def test_bad_tool_args_and_bad_submission_go_back_as_errors(repo):
    bad_call = {"type": "tool_use", "id": "toolu_1", "name": "search_events",
                "input": {"host": "WS-03; rm", "start": "x", "end": "y", "field": None, "value": None, "limit": None}}
    bad_submit = {"type": "tool_use", "id": "toolu_2", "name": "submit_verdict",
                  "input": {**fixture_turns("A-007")[-1]["response"]["content"][1]["input"], "verdict": "approved"}}
    good = fixture_turns("A-007")[-1]["response"]
    client = ScriptedClient([response([bad_call], "tool_use"), response([bad_submit], "tool_use"), good])
    _, verdict = investigate("A-007", client, repo, run_id="20261027T000000Z-live")
    first, second = client.requests[1]["messages"][-1]["content"][0], client.requests[2]["messages"][-1]["content"][0]
    assert first["is_error"] and "bad host" in first["content"]
    assert second["is_error"] and "verdict: one of" in second["content"]
    assert verdict["verdict"] == "malicious"


def test_request_shape(repo):
    client = ScriptedClient([fixture_turns("A-012")[-1]["response"]])
    investigate("A-012", client, repo, run_id="20261027T000000Z-live")
    req = client.requests[0]
    assert req["thinking"] == {"type": "adaptive"} and req["output_config"] == {"effort": "high"}
    assert req["tool_choice"] == {"type": "auto"} and "fallbacks" not in req and "betas" not in req
    assert all(t["strict"] is True for t in req["tools"])
    assert "<alert_card>" in req["messages"][0]["content"]


def test_lone_surrogate_in_a_recording_still_writes_the_run(repo, capsys):
    from asa.cli import say

    turns = fixture_turns("A-007")
    submit = turns[-1]["response"]["content"][1]["input"]
    submit["summary"] = "tampered " + chr(0xD800)
    submit["claims"][0]["text"] = chr(0xDFFF) + " claim"
    run_dir, verdict = investigate("A-007", ReplayClient(turns, "fixture", require_live=False), repo, run_id="20261027T000000Z-mock")
    assert json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))["summary"] == "tampered " + chr(0xD800)
    assert "tampered" in (run_dir / "case.html").read_text(encoding="utf-8")
    say(verdict["summary"])
    assert capsys.readouterr().out == "tampered ?\n"
