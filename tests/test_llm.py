import json
import math

import pytest

from asa import cli
from asa.agent import investigate, investigate_many
from asa.common import UsageError
from asa.llm import (CACHE_READ_PRICE, MAX_TOKENS, Budget, BudgetExceeded, Ledger, LiveClient, RecordingClient,
                     ReplayClient, check_model, cost_of, live_client, reserve_for)
from asa.prompt import tool_definitions
from fakes import FakeMessages, FakeSDK, ScriptedClient, fixture_turns


def canary() -> str:
    # Built from parts at runtime so no key-shaped literal sits in the repo.
    return "-".join(["sk", "ant", "canary"]) + "-" + "q" * 6 + "7" * 6


@pytest.mark.parametrize("extra", ["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_PROFILE"])
def test_live_client_refuses_redirect_env(extra):
    secret = canary()
    env = {"ANTHROPIC_API_KEY": secret, extra: "v" + secret}
    with pytest.raises(UsageError) as info:
        live_client(env)
    assert extra in str(info.value) and secret not in str(info.value)


def test_live_client_refuses_missing_key():
    with pytest.raises(UsageError, match="ANTHROPIC_API_KEY is not set"):
        live_client({})
    with pytest.raises(UsageError):
        live_client({"ANTHROPIC_API_KEY": ""})


def test_live_client_settings():
    client = live_client({"ANTHROPIC_API_KEY": canary()})  # no request is made
    assert str(client.base_url).rstrip("/") == "https://api.anthropic.com" and client.max_retries == 0


def test_cost_and_reserve_math():
    usage = {"input_tokens": 1_000_000, "output_tokens": 100_000, "cache_creation_input_tokens": 200_000,
             "cache_read_input_tokens": 500_000}
    # sonnet: 1M x $2 + 0.2M x $2 x 1.25 + 0.5M x $0.20 + 0.1M x $10
    assert math.isclose(cost_of("claude-sonnet-5-5", usage), 2.0 + 0.5 + 0.1 + 1.0)
    assert math.isclose(cost_of("claude-opus-5-5", usage), 4.0 + 1.0 + 0.5 * CACHE_READ_PRICE + 2.0)
    request = {"max_tokens": MAX_TOKENS, "messages": [{"role": "user", "content": "x" * 2970}]}
    size = len(json.dumps(request, separators=(",", ":")).encode("utf-8"))
    expected = (math.ceil(size / 3) * 2.0 * 1.25 + MAX_TOKENS * 10.0) / 1e6
    assert math.isclose(reserve_for("claude-sonnet-5-5", request), expected)


def test_unknown_model_refused():
    for call in (lambda: check_model("claude-other"), lambda: cost_of("claude-other", {}),
                 lambda: reserve_for("claude-other", {"max_tokens": 1})):
        with pytest.raises(UsageError, match="unknown model"):
            call()


def test_budget_refuses_at_the_edge(tmp_path):
    request = {"max_tokens": MAX_TOKENS, "messages": []}
    need = reserve_for("claude-sonnet-5-5", request)
    Budget(need, Ledger(tmp_path / "a.jsonl")).before("claude-sonnet-5-5", request, "A-007")  # exactly enough: allowed
    with pytest.raises(BudgetExceeded):
        Budget(need - 1e-9, Ledger(tmp_path / "b.jsonl")).before("claude-sonnet-5-5", request, "A-007")
    for bad in (0, -1, float("nan"), float("inf")):
        with pytest.raises(UsageError):
            Budget(bad, Ledger(tmp_path / "c.jsonl"))


def test_ledger_resume_after_crash_keeps_prior_spend(tmp_path):
    path = tmp_path / "out" / "ledger" / "live-20261027.jsonl"
    first = Ledger(path)
    seq = first.reserve(0.30, "A-001")
    first.actual(seq, 0.12, {"input_tokens": 1})
    first.reserve(0.25, "A-002")  # crash here: no actual line
    resumed = Ledger(path)
    assert math.isclose(resumed.spent(), 0.37)
    request = {"max_tokens": MAX_TOKENS, "messages": []}
    with pytest.raises(BudgetExceeded):
        Budget(0.37 + reserve_for("claude-sonnet-5-5", request) - 0.01, resumed).before("claude-sonnet-5-5", request, "A-003")
    assert all(line["type"] in ("reserve", "actual") for line in map(json.loads, path.read_text().splitlines()))


def test_cli_live_without_budget_refused(repo_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo_dir)
    monkeypatch.setenv("ANTHROPIC_API_KEY", canary())
    assert cli.main(["investigate", "--alert", "A-007", "--live"]) == 2
    out = capsys.readouterr().out
    assert "--live needs --budget" in out and canary() not in out


def test_cli_live_refuses_redirect_env_before_any_request(repo_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo_dir)
    monkeypatch.setenv("ANTHROPIC_API_KEY", canary())
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:9")
    assert cli.main(["investigate", "--alert", "A-007", "--live", "--budget", "1"]) == 2
    assert "ANTHROPIC_BASE_URL is set" in capsys.readouterr().out
    assert not (repo_dir / "evals" / "recorded").exists()


def test_cli_live_unknown_model_refused(repo_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo_dir)
    assert cli.main(["investigate", "--alert", "A-007", "--live", "--budget", "1", "--model", "claude-other"]) == 2
    assert "unknown model" in capsys.readouterr().out


def test_early_stop_marks_incomplete_with_n_done(repo, dataset):
    from asa.agent import build_request
    from asa.prompt import first_message

    submit = fixture_turns("A-012")[-1]["response"]  # one turn per alert
    submit["usage"] = {"input_tokens": 50_000, "output_tokens": 1_000}
    actual = cost_of("claude-sonnet-5-5", submit["usage"])
    order = ["A-012", "A-021", "A-007"]
    reserve = {a: reserve_for("claude-sonnet-5-5", build_request("claude-sonnet-5-5", "high", [
        {"role": "user", "content": first_message(dataset.alerts[a])}])) for a in order}
    limit = 2 * actual + reserve["A-007"] - 0.001  # the third reserve no longer fits
    assert actual + reserve["A-021"] <= limit
    sdk = FakeSDK([submit])
    budget = Budget(limit, Ledger(repo.path("out", "ledger", "live-20261027.jsonl", write=True)))
    result = investigate_many(order, lambda a: LiveClient(sdk, "claude-sonnet-5-5", "high", budget), repo, "20261027T000000Z-live")
    assert (result["planned"], result["n"], result["incomplete"]) == (3, 2, True)
    assert [v["alert_id"] for v in result["verdicts"]] == ["A-012", "A-021"] and sdk.messages.calls == 2


def test_api_error_on_one_alert_is_recorded_and_the_run_goes_on(repo):
    class OverloadedError(Exception):
        status_code = 529

    class FlakyMessages(FakeMessages):
        def create(self, **request):
            if self.calls == 0:
                self.calls += 1
                raise OverloadedError("server detail that must not be printed")
            return super().create(**request)

    sdk = FakeSDK([fixture_turns("A-012")[-1]["response"]])
    sdk.messages = FlakyMessages(sdk.messages.responses)
    budget = Budget(4.0, Ledger(repo.path("out", "ledger", "live-20261027.jsonl", write=True)))
    lines = []
    result = investigate_many(["A-012", "A-021"], lambda a: LiveClient(sdk, "claude-sonnet-5-5", "high", budget),
                              repo, "20261027T000000Z-live", echo=lines.append)
    assert (result["planned"], result["n"], result["incomplete"], result["stopped"]) == (2, 1, True, None)
    assert result["failed"] == [{"alert_id": "A-012", "error": "model API error: OverloadedError (HTTP 529)"}]
    assert [v["alert_id"] for v in result["verdicts"]] == ["A-021"]
    assert any("A-012: failed" in line for line in lines) and "server detail" not in json.dumps(result)


def test_early_stop_on_first_request(repo):
    sdk = FakeSDK([fixture_turns("A-012")[-1]["response"]])
    budget = Budget(0.0001, Ledger(repo.path("out", "ledger", "live-20261027.jsonl", write=True)))
    result = investigate_many(["A-012", "A-021"], lambda a: LiveClient(sdk, "claude-sonnet-5-5", "high", budget),
                              repo, "20261027T000000Z-live")
    assert result == {"run_id": "20261027T000000Z-live", "planned": 2, "n": 0, "incomplete": True,
                      "stopped": result["stopped"], "failed": [], "verdicts": []}
    assert "budget reached" in result["stopped"] and sdk.messages.calls == 0


def with_signatures(turns):
    out = []
    for t in turns:
        r = json.loads(json.dumps(t["response"]))
        for block in r["content"]:
            if block["type"] == "thinking":
                block["signature"] = "sig-" + "z" * 40
        r["content"].append({"type": "redacted_thinking", "data": "opaque-" + "y" * 30})
        out.append(r)
    return out


def test_recording_round_trip_strips_signatures_and_never_holds_the_key(repo, repo_dir, monkeypatch):
    secret = canary()
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
    scripted = ScriptedClient(with_signatures(fixture_turns("A-007")))
    _, live_verdict = investigate("A-007", RecordingClient(scripted, repo, "live-20261027"), repo, run_id="20261027T000001Z-live")
    rec = repo_dir / "evals" / "recorded" / "live-20261027" / "A-007" / "turns.jsonl"
    text = rec.read_text(encoding="utf-8")
    assert '"signature"' not in text and "opaque-" not in text
    turns = [json.loads(x) for x in text.splitlines()]
    assert [t["turn"] for t in turns] == [1, 2, 3] and {t["source"] for t in turns} == {"live"}
    assert set(turns[0]) == {"turn", "source", "model", "effort", "recorded_at", "response", "tool_results"}
    replayed = ReplayClient(turns, "live-20261027")
    _, verdict = investigate("A-007", replayed, repo, run_id="20261027T000002Z-mock")
    keep = ("verdict", "confidence", "summary", "claims", "injection_reports", "recommended_actions")
    assert {k: verdict[k] for k in keep} == {k: live_verdict[k] for k in keep}
    for path in repo_dir.rglob("*"):
        if path.is_file():
            body = path.read_text(encoding="utf-8", errors="replace")
            assert secret not in body and '"signature"' not in body, path


def test_recording_refuses_to_overwrite(repo):
    first = RecordingClient(ScriptedClient([fixture_turns("A-012")[-1]["response"]]), repo, "live-20261027")
    investigate("A-012", first, repo, run_id="20261027T000001Z-live")
    again = RecordingClient(ScriptedClient([]), repo, "live-20261027")
    with pytest.raises(UsageError, match="already recorded"):
        again.begin("A-012")


def walk(schema, path="$"):
    yield path, schema
    if isinstance(schema, dict):
        for key, value in schema.items():
            yield from walk(value, f"{path}.{key}")
    elif isinstance(schema, list):
        for i, value in enumerate(schema):
            yield from walk(value, f"{path}[{i}]")


def test_strict_schema_lint():
    for tool in tool_definitions():
        assert tool["strict"] is True
        for path, node in walk(tool["input_schema"], tool["name"]):
            if not isinstance(node, dict):
                continue
            for banned in ("minimum", "maximum", "maxLength", "minLength", "pattern", "maxItems", "minItems"):
                assert banned not in node, (path, banned)
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False, path
                assert sorted(node.get("required", [])) == sorted(node["properties"]), path
