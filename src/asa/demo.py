"""`asa demo`: the whole story at $0 in one command, then the folder to open.

1 replay all 30 recorded alerts (no model call)   2 threat intel (post-triage, synthetic provider answers)
3 two scripted dry-run approvals                   4 evidence check
5 trust report per alert                           6 console build (static site under out/console)

Steps 2 and 5 run through their own `asa` subcommands (`asa intel`, `asa trust`), and are reported as skipped
when a build lacks them. Nothing is executed anywhere: approvals are dry runs labelled "scripted demo approval".
"""
from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
from typing import Callable

from .common import UsageError, clean_text

DEMO_APPROVER = "scripted demo approval"
# The A-007 hand-over (the alert with a planted instruction) and the one password reset the agent recommended.
DEMO_APPROVALS = (("A-007", "ACT-001"), ("A-021", "ACT-002"))
# A fixed time (after the recording, 2026-10-29 04:12-04:22 UTC) so a replayed demo writes the same trail on any machine.
DEMO_APPROVAL_AT = "2026-10-29T05:00:00Z"
STEPS = 6


def say(line: str) -> None:
    print(clean_text(line), flush=True)


def add_parser(sub: argparse._SubParsersAction) -> None:
    demo = sub.add_parser("demo", help="replay all alerts, intel, scripted approvals, check, trust, console ($0)")
    demo.add_argument("--out", default="out/console", help="console folder inside out/ (default out/console)")
    demo.set_defaults(handler=cmd_demo)


def _parser_has(argv: list[str]) -> bool:
    """True when this version's `asa` accepts argv (a subcommand another part of the package may add)."""
    from . import cli

    try:
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            cli.build_parser().parse_args(argv)
    except SystemExit:
        return False
    return True


def _run_step(repo, argv: list[str]) -> tuple[int, str]:
    """Run one `asa` subcommand in-process against `repo`, output captured. Returns (exit code, last line)."""
    from . import cli

    parser = cli.build_parser()
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(buf):
            args = parser.parse_args(argv)
            handler = getattr(args, "handler", None) or getattr(cli, "cmd_" + argv[0].replace("-", "_"), None)
            if handler is None:
                return 2, f"no handler for {argv[0]}"
            code = handler(args, repo)
    except SystemExit as exc:
        return int(exc.code or 0) if isinstance(exc.code, int) else 2, "bad arguments"
    except UsageError as exc:
        return 2, str(exc)
    lines = [x for x in buf.getvalue().splitlines() if x.strip()]
    return int(code or 0), lines[-1] if lines else ""


def _run_ids(repo) -> set[str]:
    from .common import RUN_ID

    root = repo.path("out", "runs")
    return {p.name for p in root.iterdir() if p.is_dir() and RUN_ID.fullmatch(p.name)} if root.is_dir() else set()


def replay_all(repo, echo: Callable[[str], None]) -> tuple[str, dict]:
    """Replay every alert into one new run. Returns (run_id, investigate_many-style result)."""
    from .agent import investigate_many
    from .cli import newest_recording
    from .evals import fresh_run_id
    from .llm import ReplayClient
    from .tools import Dataset

    recording = newest_recording(repo)
    ids = sorted(Dataset(repo).alerts)
    if _parser_has(["investigate", "--mock", "--all"]):
        # The package's own "replay everything" path (it owns the run id and the trail's fixed clock).
        before = _run_ids(repo)
        code, last = _run_step(repo, ["investigate", "--mock", "--all"])
        new = sorted(_run_ids(repo) - before)
        if code not in (0, 1) or len(new) != 1:
            raise UsageError(f"replay of all alerts failed: {last[:200]}")
        run_id = new[0]
        done = sorted(p.name for p in repo.path("out", "runs", run_id).iterdir() if (p / "verdict.json").is_file())
        result = {"run_id": run_id, "planned": len(ids), "n": len(done), "incomplete": len(done) < len(ids) or code != 0,
                  "failed": [{"alert_id": a, "error": "no verdict"} for a in ids if a not in done]}
    else:
        run_id = fresh_run_id(repo, "mock")

        def client(alert_id: str) -> ReplayClient:
            return ReplayClient.from_dir(repo.path("evals/recorded", recording, alert_id), recording, require_live=True)

        result = investigate_many(ids, client, repo, run_id)
    echo(f"1/{STEPS} replay: {result['n']} of {result['planned']} alerts from recording {recording} into out/runs/{run_id} "
         "($0, no model call)")
    for failed in result["failed"]:
        echo(f"  {failed['alert_id']} failed: {failed['error']}")
    return run_id, result


def _per_alert(repo, run_dirs: list[Path], command: str, step: int, label: str, echo: Callable[[str], None]) -> bool:
    if not run_dirs or not _parser_has([command, repo.rel(run_dirs[0])]):
        echo(f"{step}/{STEPS} {label}: skipped (this version has no `asa {command}`)")
        return True
    failed = []
    for run_dir in run_dirs:
        code, last = _run_step(repo, [command, repo.rel(run_dir)])
        if code != 0:
            failed.append(f"{run_dir.name} ({last[:120]})")
    echo(f"{step}/{STEPS} {label}: {len(run_dirs) - len(failed)} of {len(run_dirs)} alerts")
    for line in failed:
        echo(f"  {command} failed for {line}")
    return not failed


def approve_scripted(run_dirs: dict[str, Path], echo: Callable[[str], None]) -> bool:
    from .actions import approve, recommended

    done, messages = [], []
    for alert_id, action_id in DEMO_APPROVALS:
        run_dir = run_dirs.get(alert_id)
        if run_dir is None or action_id not in {a["id"] for a in recommended(run_dir)}:
            echo(f"  {alert_id} {action_id}: not in this run, no approval")
            continue
        written, message = approve(run_dir, action_id, DEMO_APPROVER, at=DEMO_APPROVAL_AT)
        messages.append(f"  {alert_id}: {message}")  # what approve() did, e.g. "already approved ...; nothing changed"
        if written:
            done.append(f"{alert_id} {action_id}")
    echo(f"3/{STEPS} approvals: {', '.join(done) or 'none new'} approved as dry runs by \"{DEMO_APPROVER}\" (nothing is sent)")
    for line in messages:
        echo(line)
    return True


def run(repo, out_text: str = "out/console", echo: Callable[[str], None] = say) -> int:
    from .checker import check_run
    from .console.build import build
    from .console.cli import out_arg, report
    from .tools import Dataset

    out_dir = out_arg(repo, out_text)  # checked before any work
    echo("asa demo: synthetic data, $0, no model call, nothing executed")
    run_id, result = replay_all(repo, echo)
    runs_dir = repo.path("out", "runs", run_id)
    run_dirs = {p.name: p for p in sorted(runs_dir.iterdir()) if (p / "verdict.json").is_file()}
    ok = not result["incomplete"]
    ok &= _per_alert(repo, list(run_dirs.values()), "intel", 2, "intel (post-triage enrichment, synthetic provider answers)", echo)
    ok &= approve_scripted(run_dirs, echo)
    data = Dataset(repo)
    findings = sum(len(check_run(repo, d, data=data)["findings"]) for d in run_dirs.values())
    echo(f"4/{STEPS} evidence check: {len(run_dirs)} alerts, {findings} findings")
    ok &= _per_alert(repo, list(run_dirs.values()), "trust", 5, "trust reports", echo)
    echo(f"6/{STEPS} console:")
    code = report(build(repo, runs_dir, out_dir), echo)
    return 0 if ok and code == 0 else 1


def cmd_demo(args: argparse.Namespace, repo) -> int:
    return run(repo, args.out)
