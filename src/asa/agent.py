"""The manual tool-use loop: one alert in, a run folder out (transcript.jsonl, verdict.json, case.html, audit.jsonl).

The loop is ours, not the SDK's, so every turn passes through the client (budget check, recording) and every
tool argument goes through the tools' own checks. The model never touches files, the network or an action.
Every step also goes into the run's hash-chained audit trail (audit.py): run_start, each model turn with its usage,
each tool call and result by hash, the verdict and run_end. A replay writes the same trail, on the recording's clock.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterable

from . import case_page
from .audit import Trail, tool_call_record
from .common import ACTION_ID, ALERT_ID, EVENT_ID, Repo, UsageError, append_jsonl, check_id, new_run_id, write_json
from .llm import MAX_TOKENS, BudgetExceeded, cost_of, strip_signatures, tool_result_record
from .prompt import ACTIONS, CONFIDENCE, NUDGE, SYSTEM, VERDICTS, first_message, tool_definitions
from .tools import Dataset, ToolError

MAX_TURNS = 12
STOP_NOTES = {"refusal": "refused", "max_tokens": "out of tokens", "end_turn": "no verdict"}
USAGE_KEYS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
MAX_TEXT = 2000
MAX_ITEMS = 50


def build_request(model: str, effort: str, messages: list[dict]) -> dict:
    return {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM,
        "tools": tool_definitions(),
        "tool_choice": {"type": "auto"},
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": effort},
        "cache_control": {"type": "ephemeral"},
        "messages": messages,
    }


def _text(value: Any, what: str, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"{what}: a string of at most {limit} characters")
    return value


def _list(value: Any, what: str) -> list:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(f"{what}: a list of at most {MAX_ITEMS} items")
    return value


def _event_ids(value: Any, what: str) -> list[str]:
    ids = _list(value, what)
    for event_id in ids:
        if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id):
            raise ValueError(f"{what}: event ids look like E-000103")
    return ids


def validate_submission(data: Any) -> dict:
    """Check the model's submit_verdict input in code (the schema is strict, but replays and edge cases are not)."""
    if not isinstance(data, dict):
        raise ValueError("submit_verdict input must be an object")
    if data.get("verdict") not in VERDICTS:
        raise ValueError(f"verdict: one of {', '.join(VERDICTS)}")
    if data.get("confidence") not in CONFIDENCE:
        raise ValueError(f"confidence: one of {', '.join(CONFIDENCE)}")
    claims = []
    for c in _list(data.get("claims"), "claims"):
        if not isinstance(c, dict):
            raise ValueError("claims: objects")
        quotes = []
        for q in _list(c.get("quotes"), "quotes"):
            if not isinstance(q, dict):
                raise ValueError("quotes: objects")
            quotes.append({"event_id": _event_ids([q.get("event_id")], "quote event_id")[0],
                           "field": _text(q.get("field"), "quote field", 100), "text": _text(q.get("text"), "quote text")})
        claims.append({"text": _text(c.get("text"), "claim text"), "citations": _event_ids(c.get("citations"), "citations"),
                       "quotes": quotes})
    reports = []
    for r in _list(data.get("injection_reports"), "injection_reports"):
        if not isinstance(r, dict):
            raise ValueError("injection_reports: objects")
        reports.append({"event_id": _event_ids([r.get("event_id")], "injection event_id")[0],
                        "field": _text(r.get("field"), "injection field", 100), "excerpt": _text(r.get("excerpt"), "excerpt", 500)})
    actions, seen = [], set()
    for a in _list(data.get("recommended_actions"), "recommended_actions"):
        if not isinstance(a, dict):
            raise ValueError("recommended_actions: objects")
        action_id = a.get("id")
        if not isinstance(action_id, str) or not ACTION_ID.fullmatch(action_id) or action_id in seen:
            raise ValueError("action id: unique, like ACT-001")
        seen.add(action_id)
        if a.get("action") not in ACTIONS:
            raise ValueError(f"action: one of {', '.join(ACTIONS)}")
        actions.append({"id": action_id, "action": a["action"], "target": _text(a.get("target"), "target", 100),
                        "reason": _text(a.get("reason"), "reason"), "citations": _event_ids(a.get("citations"), "action citations")})
    return {"verdict": data["verdict"], "confidence": data["confidence"], "summary": _text(data.get("summary"), "summary"),
            "claims": claims, "injection_reports": reports, "recommended_actions": actions}


def _no_verdict(note: str) -> dict:
    return {"verdict": "needs_human", "confidence": "low",
            "summary": f"The agent ended without its own verdict ({note}). A person must review this alert.",
            "claims": [], "injection_reports": [], "recommended_actions": []}


def _describe(name: str, args: Any) -> str:
    if not isinstance(args, dict):
        return f"{name}(?)"
    return f"{name}(" + ", ".join(f"{k}={v}" for k, v in args.items() if v is not None) + ")"


def _budget_usd(client: Any) -> float | None:
    """The hard spend cap of a live client (directly or inside a RecordingClient); None for replays and fakes."""
    for c in (client, getattr(client, "inner", None)):
        limit = getattr(getattr(c, "budget", None), "limit", None)
        if isinstance(limit, float):
            return limit
    return None


def _start_record(alert_id: str, client: Any) -> tuple[dict, str]:
    replay = client.replay_of
    budget = _budget_usd(client)
    record = {"alert_id": alert_id, "mode": "replay" if replay else "live", "model": client.model, "effort": client.effort,
              "replay_of": replay, "recording": getattr(client, "source", None),
              "recording_name": getattr(client, "recording", None), "budget_usd": budget}
    if replay:
        summary = f"start {alert_id}: replay of {replay.get('recording')} ({client.model}, effort {client.effort}), $0"
    else:
        summary = f"start {alert_id}: live run ({client.model}, effort {client.effort})" + (
            f", budget ${budget:.2f}" if budget is not None else "")
    return record, summary


def investigate(alert_id: str, client: Any, repo: Repo | None = None, run_id: str | None = None,
                echo: Callable[[str], None] = lambda line: None) -> tuple[Path, dict]:
    """Investigate one alert through `client` (live, recording, replay or a test fake). Returns (run_dir, verdict)."""
    check_id(ALERT_ID, alert_id, "alert id")
    repo = repo or Repo()
    data = Dataset(repo)
    try:
        alert = data.get_alert(alert_id)["alert"]
    except ToolError as exc:
        raise UsageError(str(exc)) from None
    run_id = run_id or new_run_id("mock" if client.replay_of else "live")
    run_dir = repo.path("out", "runs", run_id, alert_id, write=True)
    run_dir.mkdir(parents=True, exist_ok=False)
    transcript = run_dir / "transcript.jsonl"
    # A replay keeps the recording's clock (each model turn at its recorded_at, other lines at the line before),
    # so the same recording always yields the same trail; a live run uses the real time.
    fixed = client.replay_of is not None
    trail = Trail.of(run_dir, fixed_clock=fixed)
    turn_at = getattr(client, "turn_recorded_at", None) if fixed else None
    start, start_summary = _start_record(alert_id, client)
    trail.append("run_start", "code", start_summary, start, at=client.replay_of.get("recorded_at") if fixed else None)
    if hasattr(client, "begin"):
        client.begin(alert_id)

    messages: list[dict] = [{"role": "user", "content": first_message(alert)}]
    usage = {k: 0 for k in USAGE_KEYS}
    cost = 0.0
    submission, stop_note, nudged = None, None, False
    turns_used, tool_calls = 0, 0
    for turn in range(1, MAX_TURNS + 1):
        response = client.create(build_request(client.model, client.effort, messages))
        turn_usage = response.get("usage") or {}
        for k in USAGE_KEYS:
            usage[k] += int(turn_usage.get(k) or 0)
        turn_cost = cost_of(client.model, turn_usage)
        cost += turn_cost
        turns_used = turn
        content = response.get("content") or []
        stop = response.get("stop_reason")
        tool_uses = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
        line = {"turn": turn, "type": "assistant", "stop_reason": stop, "content": strip_signatures(content),
                "usage": {k: int(turn_usage.get(k) or 0) for k in USAGE_KEYS}}
        append_jsonl(transcript, line)
        trail.append("model_turn", "agent", f"turn {turn}: {stop}, {len(tool_uses)} tool calls, "
                     f"{line['usage']['input_tokens']} in / {line['usage']['output_tokens']} out tokens, ${turn_cost:.4f}",
                     line, at=turn_at() if turn_at else None)

        if stop == "tool_use" and tool_uses:
            results, records, error_note = [], [], None
            for block in tool_uses:
                if block.get("name") != "submit_verdict":
                    continue
                try:
                    submission = validate_submission(block.get("input"))
                except ValueError as exc:
                    error_note = f"submit_verdict refused: {exc}"
                break
            if submission is not None:
                client.tool_results([])
                echo(f"turn {turn}: submit_verdict")
                break
            for block in tool_uses:
                name, args, use_id = block.get("name"), block.get("input"), block.get("id")
                tool_calls += 1
                trail.append("tool_call", "agent", _describe(name, args)[:120], tool_call_record(use_id, name, args))
                if name == "submit_verdict":
                    result, is_error = {"error": error_note}, True
                else:
                    try:
                        result, is_error = data.call(name, args), False
                    except ToolError as exc:
                        result, is_error = {"error": str(exc)}, True
                echo(f"turn {turn}: {_describe(name, args)}" + (" -> refused" if is_error else _count(result)))
                records.append(tool_result_record(use_id, name, args, result))
                result_line = {"turn": turn, "type": "tool_result", "tool_use_id": use_id, "name": name,
                               "input": args, "is_error": is_error, "result": result}
                append_jsonl(transcript, result_line)
                trail.append("tool_result", "code", str(name)[:40] + (" -> refused" if is_error else _count(result)),
                             result_line)
                results.append({"type": "tool_result", "tool_use_id": use_id, "is_error": is_error,
                                "content": json.dumps(result, ensure_ascii=False)})
            client.tool_results(records)
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": results})
            continue

        client.tool_results([])
        if nudged:
            stop_note = STOP_NOTES.get(stop, "no verdict")
            break
        nudged = True
        echo(f"turn {turn}: stopped ({stop}); nudging once")
        if stop == "end_turn" and content:
            messages.append({"role": "assistant", "content": content})
        # After a refusal or a cut-off turn the partial reply is dropped; consecutive user turns are allowed.
        messages.append({"role": "user", "content": NUDGE})
    else:
        stop_note = "turn limit"

    verdict = {"alert_id": alert_id, **(submission or _no_verdict(stop_note)), "stop_note": stop_note,
               "model": client.model, "effort": client.effort, "replay_of": client.replay_of,
               "usage": {"input_tokens": usage["input_tokens"], "output_tokens": usage["output_tokens"],
                         "cache_creation_tokens": usage["cache_creation_input_tokens"],
                         "cache_read_tokens": usage["cache_read_input_tokens"], "cost_usd": round(cost, 6)}}
    write_json(run_dir / "verdict.json", verdict)
    trail.append("verdict", "agent", f"verdict {verdict['verdict']} ({verdict['confidence']}), {len(verdict['claims'])} claims, "
                 f"{len(verdict['injection_reports'])} injection reports, {len(verdict['recommended_actions'])} recommended actions",
                 verdict)
    case_page.write(run_dir / "case.html", verdict, alert, data, run_id)
    if hasattr(client, "end"):
        client.end(verdict)
    end = {"alert_id": alert_id, "verdict": verdict["verdict"], "stop_note": stop_note, "turns": turns_used,
           "tool_calls": tool_calls, "cost_usd": verdict["usage"]["cost_usd"]}
    trail.append("run_end", "code", f"end {alert_id}: {verdict['verdict']}, {turns_used} turns, {tool_calls} tool calls, "
                 f"${end['cost_usd']:.4f}", end)
    return run_dir, verdict


def _count(result: dict) -> str:
    if "events" in result:
        return f" -> {result['count']} events" + (" (truncated)" if result.get("truncated") else "")
    return " -> ok"


def investigate_many(alert_ids: Iterable[str], make_client: Callable[[str], Any], repo: Repo, run_id: str,
                     echo: Callable[[str], None] = lambda line: None) -> dict:
    """Several alerts in one run. A budget stop ends the run early: the result is marked incomplete with n = k done.
    An error on one alert (a model API error, a bad recording) is recorded under `failed` and the run goes on."""
    planned = list(alert_ids)
    done, failed, stopped = [], [], None
    for alert_id in planned:
        try:
            _, verdict = investigate(alert_id, make_client(alert_id), repo, run_id, echo)
        except BudgetExceeded as exc:
            stopped = str(exc)
            break
        except UsageError as exc:
            failed.append({"alert_id": alert_id, "error": str(exc)})
            echo(f"{alert_id}: failed ({exc}); continuing")
            continue
        done.append(verdict)
    return {"run_id": run_id, "planned": len(planned), "n": len(done), "incomplete": stopped is not None or bool(failed),
            "stopped": stopped, "failed": failed, "verdicts": done}
