"""Model clients and spend control: the live client (the only network path), recording and replay, the budget and its ledger.

Every client has the same small interface used by the agent loop:
  `model`, `effort`, `replay_of` (None or {recording, model, recorded_at}),
  `create(request) -> dict` (one Messages API response body) and `tool_results(results)` (called after every turn).
"""
from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path
from typing import Any, Mapping

from .common import RECORDING, Repo, UsageError, append_jsonl, check_id, read_jsonl, sha256_json, utc_now, write_json

API_URL = "https://api.anthropic.com"
MAX_TOKENS = 16000
EFFORTS = ("low", "medium", "high", "xhigh", "max")
# USD per million tokens: (input, output). Cache writes cost 1.25x input; cache reads a flat rate.
PRICES = {"claude-sonnet-5-5": (2.00, 10.00), "claude-opus-5-5": (4.00, 20.00)}
CACHE_WRITE_FACTOR = 1.25
CACHE_READ_PRICE = 0.20
# Written next to turns.jsonl once an alert's loop has finished. A turns.jsonl without it is a partial recording
# (a budget stop or an API error mid-alert): replays refuse it, and a resumed live run moves it to out/partial/.
COMPLETE = "complete.json"
# Env vars that would send the SDK to another credential or endpoint; a live run refuses to start if any is set.
REDIRECT_ENV = ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_PROFILE")


class BudgetExceeded(Exception):
    """The next request could cost more than what is left of --budget; nothing was sent."""


class LedgerError(UsageError, ValueError):
    """The spend ledger cannot be trusted (unreadable, or an amount that is not a finite number >= 0): refuse, never assume $0."""


class ReplayMismatch(UsageError):
    """A replayed run asked for a different tool call, or got a different tool result, than the recording."""


def check_model(model: str) -> str:
    if model not in PRICES:
        raise UsageError(f"unknown model (no price): use one of {', '.join(PRICES)}")
    return model


def check_effort(effort: str) -> str:
    if effort not in EFFORTS:
        raise UsageError(f"bad effort: use one of {', '.join(EFFORTS)}")
    return effort


def cost_of(model: str, usage: Mapping[str, Any]) -> float:
    """Actual cost of one response from its `usage` block."""
    price_in, price_out = PRICES[check_model(model)]
    return (int(usage.get("input_tokens") or 0) * price_in
            + int(usage.get("cache_creation_input_tokens") or 0) * price_in * CACHE_WRITE_FACTOR
            + int(usage.get("cache_read_input_tokens") or 0) * CACHE_READ_PRICE
            + int(usage.get("output_tokens") or 0) * price_out) / 1_000_000


def reserve_for(model: str, request: Mapping[str, Any]) -> float:
    """Worst-case cost of a request before it is sent: input estimated as UTF-8 bytes / 3, priced as a cache write,
    plus max_tokens at the output price (thinking counts inside max_tokens)."""
    price_in, price_out = PRICES[check_model(model)]
    body = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")
    est_input = math.ceil(len(body) / 3)
    return (est_input * price_in * CACHE_WRITE_FACTOR + int(request["max_tokens"]) * price_out) / 1_000_000


class Ledger:
    """Append-only spend ledger (out/ledger/<recording>.jsonl): a reserve line before each request, an actual line after.
    Spent = actual where known, else the reserve (a crash between the two never lowers the total)."""

    def __init__(self, path: Path):
        self.path = path
        try:
            self.lines = read_jsonl(path) if path.exists() else []
        except (OSError, ValueError, RecursionError) as exc:
            raise LedgerError(f"cannot read the spend ledger {path.name}: {type(exc).__name__}") from None
        self.spent()  # a bad amount is refused when the ledger is opened, before any request

    def spent(self) -> float:
        reserved, actual = {}, {}
        for line in self.lines:
            try:
                usd = float(line["usd"])
                kind, seq = line["type"], line["seq"]
                if not math.isfinite(usd) or usd < 0 or isinstance(seq, (dict, list)):
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                raise LedgerError(f"bad line in the spend ledger {self.path.name}: amounts must be finite numbers >= 0") from None
            (reserved if kind == "reserve" else actual)[seq] = usd
        return sum(actual.get(seq, usd) for seq, usd in reserved.items())

    def _append(self, line: dict) -> None:
        append_jsonl(self.path, line)
        self.lines.append(line)

    def seed(self, usd: float, note: str) -> None:
        """Book spend that happened without this ledger (it was missing): a reserve and an actual line of the same amount."""
        seq = 1 + max((line["seq"] for line in self.lines), default=0)
        self._append({"seq": seq, "type": "reserve", "usd": round(usd, 6), "alert_id": None, "note": note,
                      "at": utc_now().isoformat()})
        self._append({"seq": seq, "type": "actual", "usd": round(usd, 6), "usage": None, "note": note})

    def reserve(self, usd: float, alert_id: str | None) -> int:
        seq = 1 + max((line["seq"] for line in self.lines), default=0)
        self._append({"seq": seq, "type": "reserve", "usd": round(usd, 6), "alert_id": alert_id, "at": utc_now().isoformat()})
        return seq

    def actual(self, seq: int, usd: float, usage: Mapping[str, Any]) -> None:
        keep = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
        self._append({"seq": seq, "type": "actual", "usd": round(usd, 6), "usage": {k: usage.get(k) for k in keep}})


class Budget:
    def __init__(self, limit_usd: float, ledger: Ledger):
        if not isinstance(limit_usd, (int, float)) or not math.isfinite(limit_usd) or limit_usd <= 0:
            raise UsageError("bad --budget: a positive number of US dollars")
        self.limit = float(limit_usd)
        self.ledger = ledger

    def before(self, model: str, request: Mapping[str, Any], alert_id: str | None) -> int:
        need = reserve_for(model, request)
        spent = self.ledger.spent()
        if spent + need > self.limit:
            raise BudgetExceeded(f"budget reached: spent ${spent:.4f} of ${self.limit:.2f}, next request may cost ${need:.4f}")
        return self.ledger.reserve(need, alert_id)

    def after(self, seq: int, model: str, usage: Mapping[str, Any]) -> float:
        usd = cost_of(model, usage)
        self.ledger.actual(seq, usd, usage)
        return usd


def live_client(env: Mapping[str, str] | None = None):
    """The one place a network client is built. Key from ANTHROPIC_API_KEY only, fixed base URL, no SDK retries."""
    env = os.environ if env is None else env
    for name in REDIRECT_ENV:
        if name in env:
            raise UsageError(f"{name} is set: unset it for a live run (only ANTHROPIC_API_KEY is used)")
    key = env.get("ANTHROPIC_API_KEY")
    if not key:
        raise UsageError("ANTHROPIC_API_KEY is not set (needed for --live only)")
    import anthropic

    return anthropic.Anthropic(api_key=key, base_url=API_URL, max_retries=0)


class LiveClient:
    """Sends requests through the SDK; reserves budget before each one and books the actual cost after it."""

    def __init__(self, sdk_client: Any, model: str, effort: str, budget: Budget):
        self.sdk = sdk_client
        self.model = check_model(model)
        self.effort = check_effort(effort)
        self.budget = budget
        self.replay_of = None
        self.alert_id: str | None = None

    def begin(self, alert_id: str) -> None:
        self.alert_id = alert_id

    def create(self, request: dict) -> dict:
        seq = self.budget.before(self.model, request, self.alert_id)
        try:
            response = self.sdk.messages.create(**request)
        except Exception as exc:  # SDK errors become one line; the reserve stays booked (a failed call may still bill)
            status = getattr(exc, "status_code", None)
            raise UsageError(f"model API error: {type(exc).__name__}" + (f" (HTTP {status})" if status else "")) from None
        body = response.to_dict() if hasattr(response, "to_dict") else dict(response)
        self.budget.after(seq, self.model, body.get("usage") or {})
        return body

    def tool_results(self, results: list[dict]) -> None:
        pass


def strip_signatures(value: Any) -> Any:
    """Copy of a response body without thinking signatures (and without redacted-thinking data)."""
    if isinstance(value, list):
        return [strip_signatures(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "signature" or (k == "data" and value.get("type") == "redacted_thinking"):
                continue
            out[k] = strip_signatures(v)
        return out
    return value


def tool_result_record(tool_use_id: str, name: str, args: Any, result: Any) -> dict:
    return {"tool_use_id": tool_use_id, "name": name, "input": args, "result_sha256": sha256_json(result)}


class RecordingClient:
    """Wraps a live client and writes evals/recorded/<recording>/<alert_id>/turns.jsonl, one line per model turn."""

    def __init__(self, inner: Any, repo: Repo, recording: str):
        self.inner = inner
        self.repo = repo
        self.recording = check_id(RECORDING, recording, "recording")
        self.model, self.effort, self.replay_of = inner.model, inner.effort, None
        self.path: Path | None = None
        self.turn = 0
        self.pending: dict | None = None

    def begin(self, alert_id: str) -> None:
        self.path = self.repo.path("evals/recorded", self.recording, alert_id, "turns.jsonl", write=True)
        if self.path.exists():
            raise UsageError(f"already recorded: evals/recorded/{self.recording}/{alert_id} (pick another recording name)")
        self.turn = 0
        if hasattr(self.inner, "begin"):
            self.inner.begin(alert_id)

    def end(self, verdict: dict) -> None:
        """Mark this alert's recording complete (called by the loop after verdict.json is written)."""
        if self.path is None or self.pending is not None:
            raise RuntimeError("end before the last turn was written")
        write_json(self.path.parent / COMPLETE, {"alert_id": verdict["alert_id"], "turns": self.turn, "model": self.model,
                                                 "effort": self.effort, "verdict": verdict["verdict"],
                                                 "stop_note": verdict["stop_note"]})

    def create(self, request: dict) -> dict:
        body = self.inner.create(request)
        self.turn += 1
        self.pending = {"turn": self.turn, "source": "live", "model": self.model, "effort": self.effort,
                        "recorded_at": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"), "response": strip_signatures(body)}
        return body

    def tool_results(self, results: list[dict]) -> None:
        if self.pending is None or self.path is None:
            raise RuntimeError("tool_results before create")
        append_jsonl(self.path, {**self.pending, "tool_results": results})
        self.pending = None


RECORDED_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
USAGE_FIELDS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


def check_turn(turn: Any, recording: str) -> None:
    """One recorded turn has the shape the loop relies on; a tampered or broken file is refused (exit 2), never a traceback."""
    def bad(what: str) -> UsageError:
        return UsageError(f"recording {recording} has a malformed turn ({what})")

    if not isinstance(turn, dict):
        raise bad("not an object")
    if not isinstance(turn.get("model"), str) or turn["model"] not in PRICES:
        raise bad("model")
    if not isinstance(turn.get("effort"), str) or turn["effort"] not in EFFORTS:
        raise bad("effort")
    if not isinstance(turn.get("recorded_at"), str) or not RECORDED_AT.fullmatch(turn["recorded_at"]):
        raise bad("recorded_at")
    response = turn.get("response")
    if not isinstance(response, dict) or not isinstance(response.get("content"), list):
        raise bad("response")
    usage = response.get("usage")
    if usage is not None and (not isinstance(usage, dict) or any(
            not (usage.get(k) is None or (isinstance(usage.get(k), int) and not isinstance(usage.get(k), bool)
                                          and usage.get(k) >= 0)) for k in USAGE_FIELDS)):
        raise bad("usage")
    results = turn.get("tool_results", [])
    if not isinstance(results, list) or not all(isinstance(r, dict) for r in results):
        raise bad("tool_results")


class ReplayClient:
    """Serves a recorded run turn by turn. Each tool call the agent makes must match the recording, result hash included."""

    def __init__(self, turns: list[dict], recording: str, require_live: bool = True):
        if not turns:
            raise UsageError(f"empty recording: {recording}")
        for turn in turns:
            check_turn(turn, recording)
        if require_live and any(t.get("source") != "live" for t in turns):
            raise UsageError(f"recording {recording} is not a live recording (source must be \"live\")")
        self.turns = turns
        self.model = turns[0]["model"]
        self.effort = turns[0]["effort"]
        self.replay_of = {"recording": recording, "model": self.model, "recorded_at": turns[0]["recorded_at"]}
        self.index = 0
        self.complete: Any = None  # complete.json, when the client was read from a recording folder
        # Hashes of the recording this client serves (set by from_dir); the audit trail's run_start line carries them.
        self.source: dict | None = None

    @classmethod
    def from_dir(cls, path: Path, recording: str, require_live: bool = True) -> "ReplayClient":
        turns_file = path / "turns.jsonl"
        if not turns_file.is_file():
            raise UsageError(f"no recorded turns for this alert in {recording}")
        if not (path / COMPLETE).is_file():
            raise UsageError(f"partial recording for this alert in {recording} (no {COMPLETE}): resume the live run")
        try:
            turns = read_jsonl(turns_file)
            complete = json.loads((path / COMPLETE).read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError) as exc:
            raise UsageError(f"cannot read the recording {recording}/{path.name}: {type(exc).__name__}") from None
        client = cls(turns, recording, require_live)
        client.complete = complete
        # Parsed content, not file bytes: the same hash on a checkout with other line endings.
        client.source = {"turns_sha256": sha256_json(turns), "complete_sha256": sha256_json(complete)}
        return client

    def turn_recorded_at(self) -> str | None:
        """When the turn the last create() served was recorded (the replay's clock for the audit trail)."""
        return self.turns[self.index]["recorded_at"] if self.index < len(self.turns) else None

    def begin(self, alert_id: str) -> None:
        self.index = 0

    def end(self, verdict: dict) -> None:
        """The replay used every recorded turn and reached the verdict complete.json names; otherwise the recording is not
        what it claims to be (leftover turns, or a marker from another run)."""
        if self.index != len(self.turns):
            raise ReplayMismatch(f"replay mismatch: the recording has {len(self.turns)} turns, the replay used {self.index}")
        if self.complete is None:
            return
        c = self.complete if isinstance(self.complete, dict) else {}
        expected = {"alert_id": verdict["alert_id"], "turns": len(self.turns), "verdict": verdict["verdict"]}
        for key, value in expected.items():
            if c.get(key) != value:
                raise ReplayMismatch(f"replay mismatch: {COMPLETE} {key} differs from the replay")

    def create(self, request: dict) -> dict:
        if self.index >= len(self.turns):
            raise ReplayMismatch("replay mismatch: the agent asked for more turns than were recorded")
        return self.turns[self.index]["response"]

    def tool_results(self, results: list[dict]) -> None:
        expected = self.turns[self.index].get("tool_results", [])
        self.index += 1
        if len(results) != len(expected):
            raise ReplayMismatch(f"replay mismatch at turn {self.index}: {len(results)} tool results, recording has {len(expected)}")
        for got, want in zip(results, expected):
            for key in ("tool_use_id", "name", "input", "result_sha256"):
                if got.get(key) != want.get(key):
                    raise ReplayMismatch(f"replay mismatch at turn {self.index}, tool {want.get('name')}: {key} differs "
                                         "(the data or the tools changed since the recording)")
