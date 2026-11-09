"""Console test inputs: the real synthetic dataset and recorded run, replayed into a temp repo, plus hand-written
trust.json / intel.json / audit.jsonl / checklist.json that follow the documented interfaces. The hand-written files
let the console be tested on its own; the end-to-end demo test uses whatever the package itself writes.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from asa.common import sha256_json

PKG = Path(__file__).resolve().parents[1]
RUN_ID = "20261104T120000Z-mock"
ZERO = "0" * 64
CODE_BASE = "https://github.com/cbahena22/audited-soc-agent/blob/main/"
HOSTILE = "</script><script>alert(1)</script><img src=x onerror=alert(2)>"


def make_repo(tmp_path: Path) -> Path:
    """A copy of the package's data/ and evals/ (dataset, answer key, results, recorded run) in a temp folder."""
    dest = tmp_path / "repo"
    dest.mkdir()
    shutil.copytree(PKG / "data", dest / "data")
    (dest / "evals").mkdir()
    for name in ("answer_key.json", "results.json"):
        shutil.copy2(PKG / "evals" / name, dest / "evals" / name)
    shutil.copytree(PKG / "evals" / "recorded", dest / "evals" / "recorded")
    return dest


def replay(repo, alert_ids=None, run_id: str = RUN_ID) -> Path:
    """Replay the recorded run for these alerts (default all) into out/runs/<run_id>/. Returns that folder."""
    from asa.agent import investigate_many
    from asa.cli import newest_recording
    from asa.llm import ReplayClient
    from asa.tools import Dataset

    recording = newest_recording(repo)
    ids = sorted(alert_ids or Dataset(repo).alerts)
    result = investigate_many(ids, lambda a: ReplayClient.from_dir(repo.path("evals/recorded", recording, a), recording),
                              repo, run_id)
    assert result["n"] == len(ids), result["failed"]
    return repo.path("out", "runs", run_id)


def chain(entries: list[dict]) -> list[dict]:
    """Trail lines in the documented form: data_sha256 of the record, prev_sha256 links, sha256 of the line without it."""
    lines, prev = [], ZERO
    for seq, (kind, actor, summary, record) in enumerate(entries, 1):
        line = {"seq": seq, "at": f"2026-10-28T10:00:{seq:02d}Z", "kind": kind, "actor": actor, "summary": summary,
                "data_sha256": sha256_json(record), "prev_sha256": prev}
        line["sha256"] = sha256_json(line)
        lines.append(line)
        prev = line["sha256"]
    return lines


def write_jsonl(path: Path, lines: list[dict]) -> None:
    path.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in lines), encoding="utf-8", newline="\n")


def fake_verify(run_dir: Path):
    """A test stand-in for the trail verifier: (ok, first_bad_seq, reason) over the links and line hashes only."""
    prev = ZERO
    for i, raw in enumerate((run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        line = json.loads(raw)
        body = {k: v for k, v in line.items() if k != "sha256"}
        if line.get("seq") != i or line.get("prev_sha256") != prev or sha256_json(body) != line.get("sha256"):
            return False, i, "line hash or link does not match"
        prev = line["sha256"]
    return True, None, None


def add_trust_files(run_dir: Path, intel: bool = True) -> None:
    """Hand-written trust.json, intel.json and audit.jsonl for one replayed alert, consistent with its verdict."""
    verdict = json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))
    alert_id = verdict["alert_id"]
    cited = sorted({c for claim in verdict["claims"] for c in claim["citations"]})
    approvals = []
    if (run_dir / "approvals.jsonl").is_file():
        approvals = [json.loads(x) for x in (run_dir / "approvals.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    entries = [("run_start", "code", f"replay of live-20261028 for {alert_id}", {"alert_id": alert_id}),
               ("model_turn", "agent", "turn 1: 2 tool calls", {"turn": 1}),
               ("tool_call", "agent", "search_events(host=WS-03)", {"tool": "search_events"}),
               ("tool_result", "code", "12 events", {"count": 12}),
               ("verdict", "agent", f"verdict {verdict['verdict']}", verdict),
               ("check", "code", "0 findings", {"findings": []})]
    entries += [("approval", f"person:{a['by']}", f"{a['id']} approved (dry run)", a) for a in approvals]
    indicators = []
    if intel:
        indicators = [{"type": "ipv4", "value": "198.51.100.23", "from_event_ids": cited[:1], "verdict": "review",
                       "rule": "conflicting providers",
                       "providers": {"vt": {"status": "found", "fields": {"malicious": 2, "harmless": 60}, "fetched_at": "2026-10-28T10:00:00Z"},
                                     "abuseipdb": {"status": "found", "fields": {"abuse_confidence": 0}, "fetched_at": "2026-10-28T10:00:00Z"},
                                     "otx": {"status": "not_found", "fields": {}, "fetched_at": "2026-10-28T10:00:00Z"}}},
                      {"type": "domain", "value": "updates.corp.example", "from_event_ids": cited[:1], "verdict": "clear",
                       "rule": "own tenant allowlist", "providers": {}}]
        (run_dir / "intel.json").write_text(json.dumps({"run": f"out/runs/{run_dir.parent.name}/{alert_id}", "alert_id": alert_id,
                                                        "source": "fixtures", "indicators": indicators}, indent=2), encoding="utf-8")
        entries.append(("intel", "code", f"{len(indicators)} indicators", {"indicators": len(indicators)}))
    entries.append(("run_end", "code", "run complete", {"alert_id": alert_id}))
    lines = chain(entries)
    write_jsonl(run_dir / "audit.jsonl", lines)
    reports = verdict["injection_reports"]
    trust = {
        "run": f"out/runs/{run_dir.parent.name}/{alert_id}", "alert_id": alert_id, "generated_at": "2026-11-04T12:00:00Z",
        "model": verdict["model"], "effort": verdict["effort"], "replay_of": verdict["replay_of"],
        "data_read": {"tools_called": {"search_events": 3, "process_tree": 1}, "events_cited": len(cited), "events_seen": 40},
        "evidence": {"claims": len(verdict["claims"]), "supported": len(verdict["claims"]), "findings_by_kind": {}},
        "injection": {"reported": [r["event_id"] for r in reports], "planted_known": bool(reports), "followed": 0 if reports else None},
        "actions": {"recommended": len(verdict["recommended_actions"]),
                    "approved": [{"id": a["id"], "by": a["by"], "at": a["at"]} for a in approvals], "executed": 0},
        "intel": ({"indicators": len(indicators), "contain": 0, "review": 1, "clear": 1, "source": "fixtures"} if intel else None),
        "cost": {"usd": verdict["usage"]["cost_usd"], "turns": 4, "budget_usd": None},
        "audit": {"lines": len(lines), "head_sha256": lines[-1]["sha256"], "verified": True},
        "limits": ["The evidence checker proves a quote exists, not that the conclusion is right.",
                   "A hash chain shows edits; it does not stop someone rewriting the whole chain."],
    }
    (run_dir / "trust.json").write_text(json.dumps(trust, indent=2), encoding="utf-8")


CHECKLIST = [
    {"id": "Q01", "question": "Can it change anything in my environment?", "answer": "No. Its tools only read.",
     "console_view": "trust:A-007#rows", "code": ["src/asa/tools.py::Dataset"], "tests": ["tests/test_tools.py::test_x"],
     "limits": "Approvals are dry runs."},
    {"id": "Q02", "question": "Can a planted instruction in a log redirect it?", "answer": "It reports them.",
     "console_view": "case:A-007#injection", "code": ["src/asa/checker.py::injection_matches"], "tests": [],
     "limits": "A known set of six."},
    {"id": "Q03", "question": "Can the record be edited afterwards?", "answer": "Edits show.", "console_view": "audit:A-007#chain",
     "code": ["src/asa/audit.py::verify"], "tests": ["tests/test_audit.py::test_tamper"], "limits": "Tamper-evident only."},
    {"id": "Q04", "question": "What does intel add?", "answer": "Post-triage enrichment.", "console_view": "case:A-007#intel",
     "code": [], "tests": [], "limits": "Synthetic answers.", "pending": True},
    {"id": "Q05", "question": "Odd row", "answer": HOSTILE, "console_view": "case:A-999", "code": ["../etc/passwd::x", "javascript:alert(1)"],
     "tests": ["https://evil.example/x"], "limits": HOSTILE},
]


def add_checklist(repo_dir: Path, rows=None) -> None:
    (repo_dir / "checklist").mkdir(exist_ok=True)
    (repo_dir / "checklist" / "checklist.json").write_text(json.dumps(CHECKLIST if rows is None else rows, indent=2), encoding="utf-8")


def approve_demo(runs_dir: Path) -> None:
    from asa.actions import approve

    approve(runs_dir / "A-007", "ACT-001", "scripted demo approval")
    approve(runs_dir / "A-021", "ACT-002", "scripted demo approval")


def full_run(tmp_path: Path, alert_ids=None):
    """(repo, runs_dir): replayed, checked, two approvals, hand-written trust/intel/trail files, a checklist."""
    from asa.checker import check_run
    from asa.common import Repo

    repo_dir = make_repo(tmp_path)
    add_checklist(repo_dir)
    repo = Repo(repo_dir)
    runs_dir = replay(repo, alert_ids)
    names = {p.name for p in runs_dir.iterdir()}
    if {"A-007", "A-021"} <= names:
        approve_demo(runs_dir)
    for run_dir in sorted(runs_dir.iterdir()):
        check_run(repo, run_dir)
        add_trust_files(run_dir)
    return repo, runs_dir
