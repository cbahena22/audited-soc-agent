"""Command line: investigate, check, actions, approve, audit verify, trust, intel, eval (checker | triage | injection),
shift-report, mcp, console, demo."""
from __future__ import annotations

import argparse
import math
import re
import sys
from pathlib import Path
from typing import Sequence

from .common import (ACTION_ID, ALERT_ID, RECORDING, RUN_ID, Repo, UsageError, check_id, clean_text, recording_date,
                     run_dir_arg, utc_now)

NO_RECORDING = "no recorded live run yet: --mock replays evals/recorded/live-*, which a live run creates"


def say(line: str) -> None:
    print(clean_text(line), flush=True)


def newest_recording(repo: Repo) -> str:
    root = repo.path("evals/recorded")
    names = sorted(p.name for p in root.iterdir() if p.is_dir() and RECORDING.fullmatch(p.name)) if root.is_dir() else []
    if not names:
        raise UsageError(NO_RECORDING)
    return names[-1]


def _budget(value: str) -> float:
    try:
        usd = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("a number of US dollars, e.g. 4.00") from None
    if not math.isfinite(usd) or usd <= 0:
        raise argparse.ArgumentTypeError("a positive number of US dollars")
    return usd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asa", description="Read-only alert triage over a synthetic dataset.")
    sub = parser.add_subparsers(dest="command", required=True)
    inv = sub.add_parser("investigate", help="investigate one alert (or, with --mock, all of them) into out/runs/")
    which = inv.add_mutually_exclusive_group(required=True)
    which.add_argument("--alert", help="alert id, e.g. A-007")
    which.add_argument("--all", action="store_true", help="with --mock: replay every alert of the recording into one run")
    mode = inv.add_mutually_exclusive_group(required=True)
    mode.add_argument("--mock", action="store_true", help="replay the newest recorded live run ($0, no key, no network)")
    mode.add_argument("--live", action="store_true", help="call the model API (needs ANTHROPIC_API_KEY and --budget)")
    inv.add_argument("--budget", type=_budget, help="hard spend cap in USD for --live (required with --live)")
    inv.add_argument("--model", default="claude-sonnet-5-5")
    inv.add_argument("--effort", default="high")
    from .intel.cli import add_parser as add_intel_parser

    add_intel_parser(sub)
    sub.add_parser("mcp", help="serve the five read-only tools over stdio (JSON-RPC 2.0)")

    chk = sub.add_parser("check", help="evidence checker: deterministic checks of a run's citations and quotes (no model)")
    chk.add_argument("run_dir", help="out/runs/<run_id>/<alert_id>")
    chk.add_argument("--key", action="store_true", help="also compare the verdict with the expected result in the answer key")
    act = sub.add_parser("actions", help="list a run's recommended actions and their approval state")
    act.add_argument("run_dir", help="out/runs/<run_id>/<alert_id>")
    app = sub.add_parser("approve", help="record a dry-run approval of one action (nothing is sent or executed)")
    app.add_argument("action_id", help="action id, e.g. ACT-001")
    app.add_argument("--run", required=True, help="out/runs/<run_id>/<alert_id>")
    app.add_argument("--as", dest="by", required=True, help="who approves, a role or name, e.g. \"Night Lead\"")
    aud = sub.add_parser("audit", help="the run's hash-chained audit trail")
    aud_sub = aud.add_subparsers(dest="audit_command", required=True)
    ver = aud_sub.add_parser("verify", help="check the chain and re-hash every file it records (PASS, or the first bad line)")
    ver.add_argument("run_dir", help="out/runs/<run_id>/<alert_id>, or out/runs/<run_id> for every alert of a run")
    ver.add_argument("--head", type=_head, help="expected head sha256 kept elsewhere (catches a rewritten or cut-off trail)")
    ver.add_argument("--lines", type=_lines, help="expected line count that goes with --head")
    tru = sub.add_parser("trust", help="write trust.json for a run and print its summary (refuses a trail that does not verify)")
    tru.add_argument("run_dir", help="out/runs/<run_id>/<alert_id>")
    shift = sub.add_parser("shift-report", help="Markdown handover: open, changed and waiting items in out/runs/")
    shift.add_argument("--since", required=True, help="ISO 8601 time, e.g. 2026-10-27T00:00:00Z")

    ev = sub.add_parser("eval", help="evals against the answer key")
    ev_sub = ev.add_subparsers(dest="eval_command", required=True)
    ev_sub.add_parser("checker", help="the evidence checker's regression set: catches, known misses, false flags")
    tri = ev_sub.add_parser("triage", help="accuracy vs the answer key with a $0 severity-only baseline, cost, effort")
    src = tri.add_mutually_exclusive_group(required=True)
    src.add_argument("--recorded", help="replay a recorded live run at $0, e.g. live-20261030")
    src.add_argument("--live", action="store_true", help="record a new live run first (needs ANTHROPIC_API_KEY and --budget)")
    tri.add_argument("--budget", type=_budget, help="hard spend cap in USD for the whole recording (required with --live)")
    tri.add_argument("--pilot", type=_pilot, help="with --live: record only N more alerts, then print the projected cost")
    tri.add_argument("--out", help="with --live: name of the new recording, live-YYYYMMDD")
    tri.add_argument("--resume", help="with --live: continue this recording (its spend so far counts)")
    tri.add_argument("--model", default="claude-sonnet-5-5")
    tri.add_argument("--effort", default="high")
    inj = ev_sub.add_parser("injection", help="planted injections reported by the agent (replay, $0)")
    inj.add_argument("--recorded", help="recording to replay (default: the newest live-*)")

    from .console.cli import add_parser as add_console_parser
    from .demo import add_parser as add_demo_parser

    add_console_parser(sub)  # sets args.handler
    add_demo_parser(sub)  # sets args.handler
    return parser


def _head(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError("64 lower-case hex characters")
    return value


def _lines(value: str) -> int:
    if not re.fullmatch(r"\d{1,7}", value) or int(value) < 1:
        raise argparse.ArgumentTypeError("a whole number of lines, at least 1")
    return int(value)


def _pilot(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("a whole number of alerts, e.g. 3") from None
    if n < 1:
        raise argparse.ArgumentTypeError("at least 1 alert")
    return n


def cmd_check(args: argparse.Namespace, repo: Repo) -> int:
    from .checker import check_run, describe

    record = check_run(repo, run_dir_arg(repo, args.run_dir), use_key=args.key)
    for finding in record["findings"]:
        say(describe(finding))
    say(f"{len(record['findings'])} findings on {record['claims']} claims"
        f"{' (with the answer key)' if args.key else ''}; wrote {record['run']}/check.json")
    return 1 if record["findings"] else 0


def cmd_actions(args: argparse.Namespace, repo: Repo) -> int:
    from .actions import action_lines

    for line in action_lines(run_dir_arg(repo, args.run_dir)):
        say(line)
    return 0


def cmd_approve(args: argparse.Namespace, repo: Repo) -> int:
    from .actions import approve

    check_id(ACTION_ID, args.action_id, "action id")
    _, message = approve(run_dir_arg(repo, args.run), args.action_id, args.by)
    say(message)
    return 0


def _alert_dirs(repo: Repo, text: str) -> list[Path]:
    """out/runs/<run_id>/<alert_id> (one folder) or out/runs/<run_id> (each alert folder in it), checked part by part."""
    if not isinstance(text, str) or len(text) > 400:
        raise UsageError("bad run folder: expected out/runs/<run_id>[/<alert_id>]")
    path = Path(text)
    runs = repo.path("out", "runs")
    try:
        parts = (path if path.is_absolute() else repo.base / path).resolve().relative_to(runs).parts
    except ValueError:
        raise UsageError("bad run folder: expected out/runs/<run_id>[/<alert_id>]") from None
    if len(parts) == 2:
        return [run_dir_arg(repo, text)]
    if len(parts) != 1:
        raise UsageError("bad run folder: expected out/runs/<run_id>[/<alert_id>]")
    run = repo.path("out", "runs", check_id(RUN_ID, parts[0], "run id"))
    # a linked alert folder could point anywhere: only plain folders inside the run are verified
    dirs = sorted(p for p in run.iterdir() if not p.is_symlink() and p.is_dir() and ALERT_ID.fullmatch(p.name)) if run.is_dir() else []
    if not dirs:
        raise UsageError(f"no alert folders in out/runs/{parts[0]}")
    return dirs


def cmd_audit(args: argparse.Namespace, repo: Repo) -> int:
    from .audit import head, verify

    dirs = _alert_dirs(repo, args.run_dir)
    if (args.head or args.lines) and len(dirs) != 1:
        raise UsageError("--head / --lines anchor one alert's trail: give out/runs/<run_id>/<alert_id>")
    if args.head and not args.lines:
        raise UsageError("--head needs --lines (the line count that goes with it)")
    passed = 0
    for run_dir in dirs:
        ok, bad, why = verify(run_dir, args.head, args.lines)
        if ok:
            passed += 1
            n, sha = head(run_dir)
            say(f"PASS {repo.rel(run_dir)}: {n} lines, head {sha}")
        else:
            say(f"FAIL {repo.rel(run_dir)}" + (f" at seq {bad}" if bad else "") + f": {why}")
    if len(dirs) > 1:
        say(f"{passed} of {len(dirs)} trails verify")
    return 0 if passed == len(dirs) else 1


def cmd_trust(args: argparse.Namespace, repo: Repo) -> int:
    from .trust import TrustRefused, summary_lines, write

    run_dir = run_dir_arg(repo, args.run_dir)
    try:
        report, path = write(repo, run_dir)
    except TrustRefused as exc:
        say(f"asa trust: refused, no report written: {exc}")
        return 1
    for line in summary_lines(report):
        say(line)
    say(f"wrote {repo.rel(path)}")
    return 0


def cmd_investigate_all(args: argparse.Namespace, repo: Repo) -> int:
    from .agent import investigate_many
    from .evals import fresh_run_id
    from .llm import ReplayClient
    from .tools import Dataset

    if not args.mock:
        raise UsageError("--all is for --mock only (a live run of every alert is `asa eval triage --live`)")
    if args.budget is not None:
        raise UsageError("--budget is for --live only (--mock costs $0)")
    recording = newest_recording(repo)
    alerts = sorted(Dataset(repo).alerts)
    run_id = fresh_run_id(repo, "mock")
    say(f"replay of recorded run {recording}: {len(alerts)} alerts into out/runs/{run_id} ($0, no key, no network)")
    result = investigate_many(
        alerts, lambda a: ReplayClient.from_dir(repo.path("evals/recorded", recording, a), recording, require_live=True),
        repo, run_id)
    for v in result["verdicts"]:
        say(f"{v['alert_id']}: {v['verdict']} ({v['confidence']}), {len(v['claims'])} claims, "
            f"{len(v['injection_reports'])} injection reports, recorded cost ${v['usage']['cost_usd']:.4f}")
    for f in result["failed"]:
        say(f"{f['alert_id']}: failed ({f['error']})")
    say(f"replayed {result['n']} of {result['planned']} alerts into out/runs/{run_id}"
        + (" (INCOMPLETE)" if result["incomplete"] else "") + f"; next: asa audit verify out/runs/{run_id}")
    return 1 if result["incomplete"] else 0


def cmd_shift_report(args: argparse.Namespace, repo: Repo) -> int:
    from .shift_report import build, since_arg

    for line in build(repo, since_arg(args.since)).splitlines():
        say(line)
    return 0


def cmd_eval(args: argparse.Namespace, repo: Repo) -> int:
    from . import evals

    if args.eval_command == "checker":
        from .mutate import report_lines, run_set

        result = run_set(repo)
        for line in report_lines(result):
            say(line)
        return 0 if result["as_expected"] else 1
    if args.eval_command == "injection":
        recording = check_id(RECORDING, args.recorded, "recording") if args.recorded else newest_recording(repo)
        sections = evals.injection_recorded(repo, recording, echo=say)
        for line in evals.summary_lines(None, sections["injection"]):
            say(line)
        return 0
    if args.recorded:
        for flag in ("budget", "pilot", "out", "resume"):
            if getattr(args, flag) is not None:
                raise UsageError(f"--{flag} is for --live only (--recorded replays at $0)")
        sections = evals.triage_recorded(repo, check_id(RECORDING, args.recorded, "recording"), echo=say)
        for line in evals.summary_lines(sections["triage"], sections["injection"]):
            say(line)
        return 0
    return cmd_eval_live(args, repo)


def cmd_eval_live(args: argparse.Namespace, repo: Repo) -> int:
    from . import evals
    from .llm import check_effort, check_model, live_client

    if args.budget is None:
        raise UsageError("--live needs --budget <usd> (a hard spend cap for the whole recording)")
    if (args.out is None) == (args.resume is None):
        raise UsageError("--live needs --out <recording> for a new run or --resume <recording>")
    check_id(RECORDING, args.out or args.resume, "recording")
    check_model(args.model)
    check_effort(args.effort)
    say(f"live eval {args.out or args.resume}, {args.model}, effort {args.effort}, budget ${args.budget:.2f}"
        + (f", pilot {args.pilot} alerts" if args.pilot else ""))
    result = evals.triage_live(repo, live_client(), args.budget, args.model, args.effort, out=args.out,
                               resume=args.resume, pilot=args.pilot, echo=say)
    if result["stopped"]:
        say(f"stopped: {result['stopped']} (results incomplete)")
    say(f"recorded {result['complete']} of {result['planned']} alerts; spent ${result['spent']:.4f} of ${args.budget:.2f}"
        + (f"; projected {result['planned']} alerts: ${result['projected']:.2f}" if result["projected"] is not None else ""))
    if result["results"]:
        for line in evals.summary_lines(result["results"]["triage"], result["results"]["injection"]):
            say(line)
    if result["complete"] < result["planned"]:
        say(f"continue: asa eval triage --live --budget {args.budget:.2f} --resume {result['recording']}")
    return 1 if result["stopped"] else 0


def cmd_investigate(args: argparse.Namespace, repo: Repo) -> int:
    from .agent import investigate
    from .llm import (Budget, BudgetExceeded, Ledger, LiveClient, RecordingClient, ReplayClient, check_effort,
                      check_model, live_client)

    if args.all:
        return cmd_investigate_all(args, repo)
    alert_id = check_id(ALERT_ID, args.alert, "alert id")
    if args.mock:
        if args.budget is not None:
            raise UsageError("--budget is for --live only (--mock costs $0)")
        recording = newest_recording(repo)
        client = ReplayClient.from_dir(repo.path("evals/recorded", recording, alert_id), recording, require_live=True)
        say(f"replay of recorded run {recording}, {client.model}, {recording_date(recording)}")
    else:
        if args.budget is None:
            raise UsageError("--live needs --budget <usd> (a hard spend cap)")
        check_model(args.model)
        check_effort(args.effort)
        recording = "live-" + utc_now().strftime("%Y%m%d")
        ledger = Ledger(repo.path("out", "ledger", f"{recording}.jsonl", write=True))
        live = LiveClient(live_client(), args.model, args.effort, Budget(args.budget, ledger))
        client = RecordingClient(live, repo, recording)
        say(f"live run {recording}, {args.model}, effort {args.effort}, budget ${args.budget:.2f} "
            f"(spent so far ${ledger.spent():.4f})")
    try:
        from .evals import fresh_run_id

        run_id = fresh_run_id(repo, "mock" if args.mock else "live")
        run_dir, verdict = investigate(alert_id, client, repo, run_id=run_id, echo=say)
    except BudgetExceeded as exc:
        say(f"stopped: {exc} (results incomplete)")
        return 1
    say(f"verdict: {verdict['verdict']} ({verdict['confidence']}), {len(verdict['claims'])} claims, "
        f"{len(verdict['injection_reports'])} injection reports, ${verdict['usage']['cost_usd']:.4f}")
    say(f"case page: {repo.rel(run_dir / 'case.html')}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        repo = Repo()
        if args.command == "mcp":
            from .mcp_server import serve
            return serve(repo)
        if getattr(args, "handler", None) is not None:  # intel, console, demo register their own handler
            return args.handler(args, repo)
        commands = {"investigate": cmd_investigate, "check": cmd_check, "actions": cmd_actions, "approve": cmd_approve,
                    "audit": cmd_audit, "trust": cmd_trust, "shift-report": cmd_shift_report, "eval": cmd_eval}
        return commands[args.command](args, repo)
    except UsageError as exc:
        say(f"asa: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
