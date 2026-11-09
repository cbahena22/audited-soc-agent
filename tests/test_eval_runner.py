import json
import shutil
from pathlib import Path

import pytest

from asa import cli, evals
from asa.agent import build_request
from asa.common import Repo, UsageError
from asa.llm import cost_of, reserve_for
from asa.prompt import first_message
from asa.tools import Dataset
from fakes import FakeSDK, fixture_turns, install_recording

SUBFOLDER = Path(__file__).resolve().parents[1]
MODEL = "claude-sonnet-5-5"


def results(repo_dir):
    return json.loads((repo_dir / "evals" / "results.json").read_text(encoding="utf-8"))


def first_reserve(dataset, alert_id):
    return reserve_for(MODEL, build_request(MODEL, "high", [{"role": "user", "content": first_message(dataset.alerts[alert_id])}]))


@pytest.fixture
def no_live_client(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("a live client was built")
    monkeypatch.setattr("asa.llm.live_client", refuse)


@pytest.mark.parametrize("argv,message", [
    (["--live", "--out", "live-20261030"], "--live needs --budget"),
    (["--live", "--budget", "4"], "--live needs --out"),
    (["--live", "--budget", "4", "--out", "live-20261030", "--resume", "live-20261030"], "--live needs --out"),
    (["--live", "--budget", "4", "--out", "run-1"], "bad recording"),
    (["--live", "--budget", "4", "--out", "live-20261030", "--model", "claude-other"], "unknown model"),
    (["--recorded", "live-20261027", "--budget", "4"], "--budget is for --live only"),
    (["--recorded", "live-20261027", "--pilot", "3"], "--pilot is for --live only"),
])
def test_cli_refusals_before_any_client(repo_dir, monkeypatch, capsys, no_live_client, argv, message):
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", *argv]) == 2
    assert message in capsys.readouterr().out


def test_recorded_results_from_a_small_fixture(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 0
    out = capsys.readouterr().out
    assert "n = 3 of 3, n_malicious = 1 (few malicious examples; results on malicious alerts are indicative only)" in out
    t = results(repo_dir)["triage"]
    assert (t["n"], t["planned"], t["incomplete"], t["n_malicious"]) == (3, 3, False, 1)
    assert t["accuracy"] == {"correct": 3, "n": 3, "rate": 1.0}
    assert t["confusion"]["needs_human"] == {"malicious": 0, "benign": 0, "needs_human": 1}
    assert t["needs_human"]["k"] == 1 and t["refusals"] == 0
    assert t["unsupported_claims"] == {"k": 0, "n": 7, "runs_with_any": 0, "runs": 3}
    assert t["efforts"] == {"high": 3} and t["models"] == [MODEL] and t["recorded_dates"] == ["2026-10-27"]
    expected_costs = [round(sum(cost_of(MODEL, x["response"]["usage"]) for x in fixture_turns(a)), 6)
                      for a in ("A-007", "A-012", "A-021")]
    assert [r["cost_usd"] for r in t["per_alert"]] == expected_costs
    assert t["cost_usd"]["max"] == max(expected_costs)
    assert t["baseline"]["correct"] == 2  # A-021 is medium severity: the baseline says benign, the key says needs_human
    i = results(repo_dir)["injection"]
    assert (i["n"], i["reported"], i["alerts"]) == (1, 1, 1)
    assert (i["n_malicious"], i["limit"]) == (1, t["limit"])
    md = (repo_dir / "evals" / "results.md").read_text(encoding="utf-8")
    assert "**n_malicious = 1** (few malicious examples; results on malicious alerts are indicative only)." in md
    assert "| Baseline: severity only (high / critical -> malicious, else benign) | 3 | 2 | 67% |" in md
    assert "Reported: 1 of 1 planted" in md and str(repo_dir) not in md
    injection_part = md.split("## Planted injections")[1].split("## Per alert")[0]
    assert "**n_malicious = 1** (few malicious examples; results on malicious alerts are indicative only)." in injection_part
    raw = (repo_dir / "evals" / "results.json").read_text(encoding="utf-8")
    assert str(repo_dir) not in raw and json.dumps(str(repo_dir))[1:-1] not in raw and repo_dir.as_posix() not in raw
    assert t["per_alert"][0]["run"].startswith("out/runs/")


def test_recorded_refuses_a_fixture_source(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir, source="hand-written fixture")
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 2
    assert "is not a live recording" in capsys.readouterr().out
    assert not (repo_dir / "out" / "runs").exists() and not (repo_dir / "evals" / "results.json").exists()


def test_missing_recording_is_refused(repo_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--recorded", "live-20261099"]) == 2
    assert cli.main(["eval", "injection"]) == 2
    assert "no recording live-20261099" in capsys.readouterr().out


def test_incomplete_recording_is_marked(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir, alerts=("A-007", "A-012"))
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 0
    t = results(repo_dir)["triage"]
    assert (t["n"], t["planned"], t["incomplete"], t["not_recorded"]) == (2, 3, True, ["A-021"])
    assert "**INCOMPLETE**: n = 2 of 3 (not recorded: A-021)" in (repo_dir / "evals" / "results.md").read_text(encoding="utf-8")
    assert "INCOMPLETE n = 2 of 3" in capsys.readouterr().out


def test_partial_recording_is_skipped_by_replay_and_refused_by_mock(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir, alerts=("A-007", "A-012"))
    dest = repo_dir / "evals" / "recorded" / "live-20261027" / "A-021"
    dest.mkdir()
    (dest / "turns.jsonl").write_text(json.dumps({**fixture_turns("A-021")[0], "source": "live"}) + "\n", encoding="utf-8")
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 0
    assert results(repo_dir)["triage"]["not_recorded"] == ["A-021"]
    assert cli.main(["investigate", "--alert", "A-021", "--mock"]) == 2
    assert "partial recording for this alert in live-20261027" in capsys.readouterr().out


def test_baseline_rule_and_the_real_dataset():
    assert evals.baseline_verdict({"severity": "critical"}) == "malicious"
    assert evals.baseline_verdict({"severity": "High"}) == "malicious"
    assert evals.baseline_verdict({"severity": "medium"}) == "benign"
    assert evals.baseline_verdict({}) == "benign"
    repo = Repo(SUBFOLDER)
    data, key = Dataset(repo), evals.answer_key(repo)
    order = evals.alert_order(data, key)
    assert len(order) == 30 and sum(key[a]["expected_verdict"] == "malicious" for a in order) == 1
    correct = sum(evals.baseline_verdict(data.alerts[a]) == key[a]["expected_verdict"] for a in order)
    assert 0 < correct < 30


def submit_response():
    return fixture_turns("A-012")[-1]["response"]  # one turn: submit_verdict


def test_budget_stop_then_resume_keeps_prior_spend(repo, repo_dir, dataset):
    submit = submit_response()
    actual = cost_of(MODEL, submit["usage"])
    order = ["A-007", "A-012", "A-021"]
    reserve = {a: first_reserve(dataset, a) for a in order}
    limit = 2 * actual + reserve["A-021"] - 0.0001  # the third alert's reserve no longer fits
    assert actual + reserve["A-012"] <= limit
    sdk = FakeSDK([submit])
    first = evals.triage_live(repo, sdk, limit, MODEL, "high", out="live-20261030")
    assert "budget reached" in first["stopped"] and (first["complete"], first["planned"]) == (2, 3)
    assert first["spent"] == pytest.approx(2 * actual, abs=1e-6)
    assert first["projected"] == pytest.approx(first["spent"] / 2 * 3, abs=1e-4)
    t = first["results"]["triage"]
    assert t["incomplete"] and t["n"] == 2 and t["not_recorded"] == ["A-021"]
    assert sdk.messages.calls == 2

    # Same budget on resume: the ledger keeps the spend, so nothing more fits and no request is sent.
    again = evals.triage_live(repo, sdk, limit, MODEL, "high", resume="live-20261030")
    assert "budget reached" in again["stopped"] and sdk.messages.calls == 2

    # A higher cap finishes the run; the total is cumulative, effort is recorded per alert.
    done = evals.triage_live(repo, sdk, 4.00, MODEL, "medium", resume="live-20261030")
    assert done["stopped"] is None and done["complete"] == 3 and sdk.messages.calls == 3
    assert done["spent"] == pytest.approx(3 * actual, abs=1e-6)
    t = done["results"]["triage"]
    assert not t["incomplete"] and t["n"] == 3 and t["efforts"] == {"high": 2, "medium": 1}
    assert results(repo_dir)["triage"]["n"] == 3


def test_pilot_records_n_alerts_and_projects_the_cost(repo):
    sdk = FakeSDK([submit_response()])
    result = evals.triage_live(repo, sdk, 4.00, MODEL, "high", out="live-20261030", pilot=1)
    assert result["stopped"] is None and (result["complete"], result["planned"]) == (1, 3)
    assert result["projected"] == pytest.approx(result["spent"] * 3, abs=1e-4)
    assert result["results"]["triage"]["incomplete"]


def test_budget_stop_mid_alert_leaves_a_partial_that_resume_moves_aside(repo, repo_dir, dataset):
    turn1 = fixture_turns("A-007")[0]["response"]  # a tool call, then the run needs a second request
    sdk = FakeSDK([turn1, submit_response()])
    stop = evals.triage_live(repo, sdk, first_reserve(dataset, "A-007") + 1e-6, MODEL, "high", out="live-20261030")
    rec = repo_dir / "evals" / "recorded" / "live-20261030" / "A-007"
    assert "budget reached" in stop["stopped"] and stop["complete"] == 0 and stop["results"] is None
    assert (rec / "turns.jsonl").is_file() and not (rec / "complete.json").exists()
    assert evals.status(rec.parent, "A-007") == "partial"

    sdk2 = FakeSDK([submit_response()])
    done = evals.triage_live(repo, sdk2, 4.00, MODEL, "high", resume="live-20261030")
    assert done["complete"] == 3 and (rec / "complete.json").is_file()
    moved = repo_dir / "out" / "partial" / "live-20261030" / "A-007-1.jsonl"
    assert moved.is_file() and len(moved.read_text(encoding="utf-8").splitlines()) == 1
    assert done["spent"] > stop["spent"] > 0  # the partial's spend stays in the total


def test_resume_and_out_rules(repo):
    sdk = FakeSDK([submit_response()])
    evals.triage_live(repo, sdk, 4.00, MODEL, "high", out="live-20261030", pilot=1)
    with pytest.raises(UsageError, match="exists: continue it with --resume"):
        evals.triage_live(repo, sdk, 4.00, MODEL, "high", out="live-20261030")
    with pytest.raises(UsageError, match="no recording live-20261031 to resume"):
        evals.triage_live(repo, sdk, 4.00, MODEL, "high", resume="live-20261031")
    with pytest.raises(UsageError, match="another model"):
        evals.triage_live(repo, sdk, 4.00, "claude-opus-5-5", "high", resume="live-20261030")


def test_cli_live_prints_projection_with_a_fake_client(repo_dir, monkeypatch, capsys):
    sdk = FakeSDK([submit_response()])
    monkeypatch.setattr("asa.llm.live_client", lambda: sdk)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--live", "--budget", "4.00", "--pilot", "2", "--out", "live-20261030"]) == 0
    out = capsys.readouterr().out
    assert "recorded 2 of 3 alerts; spent $" in out and "; projected 3 alerts: $" in out
    assert "continue: asa eval triage --live --budget 4.00 --resume live-20261030" in out


def test_injection_eval(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "injection"]) == 0  # newest live-* by default
    assert "injections reported 1 of 1" in capsys.readouterr().out
    assert set(results(repo_dir)) == {"injection"}
    md = (repo_dir / "evals" / "results.md").read_text(encoding="utf-8")
    assert "**n_malicious = 1** (few malicious examples; results on malicious alerts are indicative only)." in md


def test_resume_without_the_ledger_seeds_the_recorded_spend(repo, repo_dir, dataset):
    submit = submit_response()
    actual = cost_of(MODEL, submit["usage"])
    limit = 2 * actual + first_reserve(dataset, "A-021") - 0.0001
    sdk = FakeSDK([submit])
    evals.triage_live(repo, sdk, limit, MODEL, "high", out="live-20261030", pilot=2)
    (repo_dir / "out" / "ledger" / "live-20261030.jsonl").unlink()  # e.g. resumed from a fresh clone (out/ is not committed)
    lines = []
    again = evals.triage_live(repo, sdk, limit, MODEL, "high", resume="live-20261030", echo=lines.append)
    assert "budget reached" in again["stopped"] and sdk.messages.calls == 2  # the cap still counts the pilot
    assert again["spent"] == pytest.approx(2 * actual, abs=1e-6)
    assert again["projected"] == pytest.approx(3 * actual, abs=1e-4)
    assert any(line.startswith("no ledger for live-20261030: booked $") for line in lines)


def test_stop_on_the_first_request_can_still_be_resumed(repo, dataset):
    sdk = FakeSDK([submit_response()])
    stop = evals.triage_live(repo, sdk, 0.0001, MODEL, "high", out="live-20261030")
    assert "budget reached" in stop["stopped"] and sdk.messages.calls == 0
    done = evals.triage_live(repo, sdk, 4.00, MODEL, "high", resume="live-20261030")
    assert done["complete"] == 3


@pytest.mark.parametrize("change", [
    lambda t: t.update(recorded_at=5),
    lambda t: t.update(recorded_at="<img src=x onerror=1>"),
    lambda t: t.pop("model"),
    lambda t: t.update(model="claude-other"),
    lambda t: t.update(effort=["high"]),
    lambda t: t.update(response="x"),
    lambda t: t["response"].update(content="x"),
    lambda t: t["response"].update(usage={"input_tokens": "many"}),
    lambda t: t.update(tool_results=[1]),
])
def test_tampered_recording_exits_2(repo_dir, monkeypatch, capsys, change):
    install_recording(repo_dir)
    path = repo_dir / "evals" / "recorded" / "live-20261027" / "A-012" / "turns.jsonl"
    turns = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    change(turns[0])
    path.write_text("".join(json.dumps(t) + "\n" for t in turns), encoding="utf-8")
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 2
    assert cli.main(["investigate", "--alert", "A-012", "--mock"]) == 2
    out = capsys.readouterr().out
    assert "malformed turn" in out and "Traceback" not in out
    assert not (repo_dir / "evals" / "results.md").exists()


def test_results_never_mix_two_recordings_and_survive_a_stale_file(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir)
    install_recording(repo_dir, name="live-20261028", alerts=("A-007",))
    monkeypatch.chdir(repo_dir)
    (repo_dir / "evals" / "results.json").write_text(json.dumps({"triage": {"n": 1, "recording": "live-20261027"}}),
                                                     encoding="utf-8")
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 0  # stale shape: replaced, no traceback
    assert cli.main(["eval", "injection"]) == 0  # newest is live-20261028: the other recording's triage is dropped
    assert set(results(repo_dir)) == {"injection"} and results(repo_dir)["injection"]["recording"] == "live-20261028"
    md = (repo_dir / "evals" / "results.md").read_text(encoding="utf-8")
    assert "Recording `live-20261028`." in md and "live-20261027" not in md


def test_total_line_names_the_ledger_when_there_is_one(repo, repo_dir):
    evals.triage_live(repo, FakeSDK([submit_response()]), 4.00, MODEL, "high", out="live-20261030")
    md = (repo_dir / "evals" / "results.md").read_text(encoding="utf-8")
    t = results(repo_dir)["triage"]
    assert t["ledger_spent_usd"] == pytest.approx(t["cost_usd"]["total"], abs=1e-6)
    assert "the spend ledger booked $" in md


@pytest.mark.parametrize("value", [["x"], {"a": 1}])
def test_unhashable_model_in_a_recording_exits_2(repo_dir, monkeypatch, capsys, value):
    install_recording(repo_dir)
    path = repo_dir / "evals" / "recorded" / "live-20261027" / "A-012" / "turns.jsonl"
    turns = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    turns[0]["model"] = value
    path.write_text("".join(json.dumps(t) + "\n" for t in turns), encoding="utf-8")
    monkeypatch.chdir(repo_dir)
    for argv in (["eval", "triage", "--recorded", "live-20261027"], ["eval", "injection"],
                 ["investigate", "--alert", "A-012", "--mock"]):
        assert cli.main(argv) == 2
    assert "Traceback" not in capsys.readouterr().out


def test_corrupt_ledger_refuses_a_live_run(repo, repo_dir):
    evals.triage_live(repo, FakeSDK([submit_response()]), 4.00, MODEL, "high", out="live-20261030", pilot=1)
    with (repo_dir / "out" / "ledger" / "live-20261030.jsonl").open("a", encoding="utf-8") as f:
        f.write("{broken\n")
    with pytest.raises(UsageError, match="cannot read the spend ledger live-20261030.jsonl"):
        evals.triage_live(repo, FakeSDK([submit_response()]), 4.00, MODEL, "high", resume="live-20261030")


def test_mock_investigate_in_the_same_second_as_an_eval_replay(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 0
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 0
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 0


@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-1.5"])
def test_nan_or_negative_ledger_amount_refuses_instead_of_lifting_the_cap(repo, repo_dir, monkeypatch, capsys, amount):
    from asa.llm import Ledger, LedgerError

    evals.triage_live(repo, FakeSDK([submit_response()]), 4.00, MODEL, "high", out="live-20261030", pilot=1)
    path = repo_dir / "out" / "ledger" / "live-20261030.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write('{"seq": 99, "type": "reserve", "usd": ' + amount + ', "alert_id": null}\n')
    with pytest.raises(LedgerError):
        Ledger(path)
    sdk = FakeSDK([submit_response()])
    with pytest.raises(UsageError, match="spend ledger"):
        evals.triage_live(repo, sdk, 4.00, MODEL, "high", resume="live-20261030")
    assert sdk.messages.calls == 0
    monkeypatch.setattr("asa.llm.live_client", lambda: sdk)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--live", "--budget", "4", "--resume", "live-20261030"]) == 2
    (repo_dir / "evals" / "recorded" / "live-20261030" / "spend.json").unlink()  # no recorded total: the ledger is read
    assert cli.main(["eval", "triage", "--recorded", "live-20261030"]) == 2  # results would name the ledger total
    assert "Traceback" not in capsys.readouterr().out and sdk.messages.calls == 0


@pytest.mark.parametrize("target", ["turns.jsonl", "complete.json"])
def test_deeply_nested_json_exits_2(repo_dir, monkeypatch, capsys, target):
    install_recording(repo_dir)
    path = repo_dir / "evals" / "recorded" / "live-20261027" / "A-012" / target
    path.write_text("[" * 5000 + "]" * 5000 + "\n", encoding="utf-8")
    monkeypatch.chdir(repo_dir)
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 2
    assert cli.main(["investigate", "--alert", "A-012", "--mock"]) == 2
    assert "Traceback" not in capsys.readouterr().out


def test_replay_must_use_every_turn_and_match_complete_json(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir)
    rec = repo_dir / "evals" / "recorded" / "live-20261027"
    monkeypatch.chdir(repo_dir)
    turns = rec / "A-012" / "turns.jsonl"
    original = turns.read_text(encoding="utf-8")
    turns.write_text(original + original.splitlines()[-1] + "\n", encoding="utf-8")  # a leftover turn after the verdict
    assert cli.main(["investigate", "--alert", "A-012", "--mock"]) == 2
    assert "the recording has 3 turns, the replay used 2" in capsys.readouterr().out
    turns.write_text(original, encoding="utf-8")
    marker = rec / "A-012" / "complete.json"
    for change in ({"verdict": "malicious"}, {"turns": 5}, {"alert_id": "A-021"}):
        data = json.loads(marker.read_text(encoding="utf-8"))
        marker.write_text(json.dumps({**data, **change}), encoding="utf-8")
        assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 2
        assert f"complete.json {next(iter(change))} differs" in capsys.readouterr().out
        marker.write_text(json.dumps({**data}), encoding="utf-8")
    assert cli.main(["eval", "triage", "--recorded", "live-20261027"]) == 0


def test_clean_clone_replay_keeps_the_recorded_ledger_total(repo, repo_dir):
    evals.triage_live(repo, FakeSDK([submit_response()]), 4.00, MODEL, "high", out="live-20261031")
    kept = json.loads((repo_dir / "evals" / "recorded" / "live-20261031" / "spend.json").read_text(encoding="utf-8"))
    first = results(repo_dir)["triage"]["ledger_spent_usd"]
    assert kept["ledger_spent_usd"] == first
    shutil.rmtree(repo_dir / "out" / "ledger")  # a clone has no local ledger
    assert evals.evaluate_recording(repo, "live-20261031")["ledger_spent_usd"] == first
    (repo_dir / "evals" / "recorded" / "live-20261031" / "spend.json").write_text('{"ledger_spent_usd": "x"}', encoding="utf-8")
    with pytest.raises(UsageError):
        evals.evaluate_recording(repo, "live-20261031")
