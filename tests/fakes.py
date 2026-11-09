"""Test doubles: a scripted client (agent-loop interface) and a fake SDK object for LiveClient."""
from __future__ import annotations

import copy
import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_turns(alert_id: str) -> list[dict]:
    path = FIXTURES / "recorded" / "fixture" / alert_id / "turns.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def response(content, stop, input_tokens=1000, output_tokens=100):
    return {"id": "msg_test", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5", "content": content,
            "stop_reason": stop, "stop_sequence": None, "stop_details": None,
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                      "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}}


class ScriptedClient:
    """Returns the given responses in order and keeps every request it was sent."""

    def __init__(self, responses, model="claude-sonnet-5-5", effort="high"):
        self.responses = [copy.deepcopy(r) for r in responses]
        self.model, self.effort, self.replay_of = model, effort, None
        self.requests: list[dict] = []
        self.results: list[list[dict]] = []

    def begin(self, alert_id):
        pass

    def create(self, request):
        self.requests.append(copy.deepcopy(request))
        if not self.responses:
            raise AssertionError("scripted client ran out of responses")
        return self.responses.pop(0)

    def tool_results(self, results):
        self.results.append(results)


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def create(self, **request):
        self.calls += 1
        return copy.deepcopy(self.responses.pop(0) if len(self.responses) > 1 else self.responses[0])


class FakeSDK:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


FIXTURE_ALERTS = ("A-007", "A-012", "A-021")
FIXTURE_VERDICTS = {"A-007": "malicious", "A-012": "benign", "A-021": "needs_human"}


def complete_marker(alert_id, turns):
    return json.dumps({"alert_id": alert_id, "turns": len(turns), "verdict": FIXTURE_VERDICTS[alert_id]})


def install_recording(repo_dir, name="live-20261027", alerts=FIXTURE_ALERTS, source="live", complete=True):
    """Copy the hand-written replays into repo_dir/evals/recorded/<name>/ as if a live run had recorded them."""
    for alert_id in alerts:
        dest = Path(repo_dir) / "evals" / "recorded" / name / alert_id
        dest.mkdir(parents=True)
        turns = fixture_turns(alert_id)
        (dest / "turns.jsonl").write_text("".join(json.dumps({**t, "source": source}) + "\n" for t in turns), encoding="utf-8")
        if complete:
            (dest / "complete.json").write_text(complete_marker(alert_id, turns), encoding="utf-8")
