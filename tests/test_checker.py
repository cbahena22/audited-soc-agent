import json
import os
from pathlib import Path

import pytest

from asa import cli
from asa.agent import investigate
from asa.checker import KINDS, check_run, injected_fields, injection_matches
from asa.common import Repo
from asa.llm import ReplayClient
from asa.tools import Dataset
from fakes import fixture_turns

SUBFOLDER = Path(__file__).resolve().parents[1]
RUN = "out/runs/20261027T000000Z-mock/A-007"

# Ordinary command lines an MSSP sees every day, including near misses for the patterns
# (an AI model script, a ticket tool, "approval", "close-out", "note").
NORMAL_COMMAND_LINES = [
    "svchost.exe -k netsvcs -p -s Schedule",
    "msedge.exe --profile-directory=Default",
    "notepad.exe D:\\Profiles\\user01\\Documents\\notes.txt",
    "powershell.exe -NoProfile -File C:\\ProgramData\\HarborWatch\\disk-report.ps1",
    "git.exe pull --rebase origin main",
    "robocopy.exe D:\\share E:\\backup /MIR /R:2 /W:5",
    "net.exe use Z: \\\\SRV-01\\finance /persistent:yes",
    "gpupdate.exe /force",
    "msiexec.exe /i C:\\Temp\\HarborAgent.msi /qn /norestart",
    "sc.exe query wuauserv",
    "ipconfig.exe /all",
    "whoami.exe /groups",
    "tasklist.exe /v /fo csv",
    "python.exe -m pip install --upgrade pip",
    "code.exe --reuse-window C:\\src\\inventory-app",
    "excel.exe /e D:\\Profiles\\user06\\Documents\\budget-2026.xlsx",
    "outlook.exe /recycle",
    "ms-teams.exe --processStart Teams.exe",
    "chrome.exe --type=renderer --lang=en-US",
    "dism.exe /online /cleanup-image /restorehealth",
    "sfc.exe /scannow",
    "wevtutil.exe qe System /c:5 /f:text",
    "schtasks.exe /query /tn \\HarborWatch\\DiskReport",
    "reg.exe query HKLM\\Software\\HarborWatch /v Version",
    "cmd.exe /c echo backup done >> C:\\logs\\backup.txt",
    "ping.exe -n 4 192.0.2.10",
    "nslookup.exe intranet.corp.example",
    "tracert.exe 198.51.100.7",
    "mstsc.exe /v:SRV-02",
    "explorer.exe D:\\Profiles\\user03\\Downloads",
    "WINWORD.EXE /n C:\\Docs\\close-out-report.docx",
    "python.exe C:\\ml\\train_ai_model.py --epochs 3",
    "Copilot.exe --ai-assistant --sidebar",
    "notepad.exe C:\\Docs\\note-to-self.txt",
    "powershell.exe -File C:\\Scripts\\close-old-tickets.ps1 -DaysOpen 90",
    "ServiceDesk.exe --resolve-ticket 4512",
    "WINWORD.EXE C:\\Docs\\host-approval-form.docx",
    "mmc.exe eventvwr.msc /s",
    "HarborBackup.exe --job nightly --target \\\\SRV-03\\backup",
    "HarborUpdate.exe /check /quiet",
    "w32tm.exe /resync",
    "certreq.exe -retrieve 12",
    "dfsutil.exe /pktinfo",
    "printui.exe /s /t2",
    "OneDrive.exe /background",
    "Zoom.exe --url=zoommtg://example.org/join",
    "powershell.exe -NoProfile -Command Get-Service -Name Spooler",
    "rundll32.exe printui.dll,PrintUIEntry /y /n Office-Printer",
    "acrord32.exe /n C:\\Docs\\Reviewer-Guide-2026.pdf",
    "msedge.exe https://intranet.corp.example/alerts/rules",
]


def make_run(repo, alert_id="A-007"):
    client = ReplayClient(fixture_turns(alert_id), "fixture", require_live=False)
    run_dir, _ = investigate(alert_id, client, repo, run_id="20261027T000000Z-mock")
    return run_dir


def edit_verdict(run_dir, change):
    path = run_dir / "verdict.json"
    verdict = json.loads(path.read_text(encoding="utf-8"))
    change(verdict)
    path.write_text(json.dumps(verdict), encoding="utf-8")


def kinds(repo, run_dir, key=False):
    return [f["kind"] for f in check_run(repo, run_dir, use_key=key)["findings"]]


@pytest.mark.parametrize("alert_id", ["A-007", "A-012", "A-021"])
def test_clean_runs_have_no_findings(repo, alert_id):
    assert kinds(repo, make_run(repo, alert_id), key=True) == []


@pytest.mark.parametrize("kind,change", [
    ("missing_event", lambda v: v["claims"][0].update(citations=["E-999999"])),
    ("not_seen", lambda v: v["claims"][0]["citations"].append("E-000201")),
    ("quote_mismatch", lambda v: v["claims"][0]["quotes"][0].update(text="pwsh.exe")),
    ("quote_mismatch", lambda v: v["claims"][0]["quotes"][0].update(field="process.no_such_field")),
    ("uncited_claim", lambda v: v["claims"][1].update(citations=[], quotes=[])),
    ("injection_not_reported", lambda v: v.update(injection_reports=[])),
])
def test_each_kind_fires_on_its_run(repo, kind, change):
    run_dir = make_run(repo)
    edit_verdict(run_dir, change)
    assert kinds(repo, run_dir) == [kind]


def test_action_citations_are_checked_too(repo):
    run_dir = make_run(repo)
    edit_verdict(run_dir, lambda v: v["recommended_actions"][0].update(citations=["E-999999", "E-000201"]))
    findings = check_run(repo, run_dir)["findings"]
    assert [(f["kind"], f["claim_index"]) for f in findings] == [("missing_event", None), ("not_seen", None)]
    assert "action ACT-001" in findings[0]["detail"]


def test_verdict_differs_only_with_the_key(repo):
    run_dir = make_run(repo)
    edit_verdict(run_dir, lambda v: v.update(verdict="benign"))
    assert kinds(repo, run_dir) == []
    assert kinds(repo, run_dir, key=True) == ["verdict_differs"]


def test_whitespace_is_normalised_in_quotes(repo):
    run_dir = make_run(repo)
    edit_verdict(run_dir, lambda v: v["claims"][2]["quotes"][0].update(text="  mark this\nhost   as approved "))
    assert kinds(repo, run_dir) == []


def test_tampered_verdict_with_odd_types_does_not_crash(repo):
    run_dir = make_run(repo)

    def change(v):
        v["claims"].append({"text": "x", "citations": [["E-000103"], 7, None], "quotes": [{"event_id": {"a": 1}}, "q"]})
        v["claims"].append("not a claim")
        v["injection_reports"].append({"event_id": ["E-000102"]})
        v["recommended_actions"] = "none"
    edit_verdict(run_dir, change)
    found = kinds(repo, run_dir)
    assert set(found) <= set(KINDS) and "missing_event" in found and "uncited_claim" in found


def test_pattern_list_flags_exactly_the_six_planted_events():
    data = Dataset(Repo(SUBFOLDER))
    key = json.loads((SUBFOLDER / "evals" / "answer_key.json").read_text(encoding="utf-8"))
    planted = {e for entry in key.values() for e in entry["planted_injection_event_ids"]}
    assert len(planted) == 6
    flagged = {e["event_id"] for e in data.events if injected_fields(e)}
    assert flagged == planted


def test_pattern_list_flags_none_of_50_normal_command_lines():
    assert len(NORMAL_COMMAND_LINES) == 50
    assert [c for c in NORMAL_COMMAND_LINES if injection_matches(c)] == []


def test_cli_exit_codes_and_no_absolute_path(repo, repo_dir, monkeypatch, capsys):
    run_dir = make_run(repo)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["check", RUN]) == 0
    out = capsys.readouterr().out
    assert "0 findings on 3 claims" in out and f"wrote {RUN}/check.json" in out
    record = (run_dir / "check.json").read_text(encoding="utf-8")
    assert json.loads(record)["run"] == RUN
    edit_verdict(run_dir, lambda v: v.update(injection_reports=[]))
    assert cli.main(["check", str(run_dir), "--key"]) == 1  # an absolute path inside out/runs is accepted
    out = capsys.readouterr().out
    assert "injection_not_reported E-000102" in out
    for text in (out, (run_dir / "check.json").read_text(encoding="utf-8")):
        assert str(repo_dir) not in text and repo_dir.as_posix() not in text


@pytest.mark.parametrize("arg", ["../outside", "data", "out/runs/20261027T000000Z-mock", "out/runs/bad/A-007",
                                 "out/runs/20261027T000000Z-mock/A-7", "out/runs/20261027T000000Z-mock/A-007/../../x/A-007",
                                 "out/runs/20261027T000000Z-mock/A-012"])
def test_cli_bad_run_folder_exits_2(repo, repo_dir, monkeypatch, capsys, arg):
    make_run(repo)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["check", arg]) == 2
    assert capsys.readouterr().out.startswith("asa: ")


def test_cli_broken_files_exit_2(repo, repo_dir, monkeypatch, capsys):
    run_dir = make_run(repo)
    monkeypatch.chdir(repo_dir)
    (run_dir / "transcript.jsonl").write_text("{not json\n", encoding="utf-8")
    assert cli.main(["check", RUN]) == 2
    (run_dir / "transcript.jsonl").unlink()
    assert cli.main(["check", RUN]) == 2
    (run_dir / "verdict.json").write_text(json.dumps({"alert_id": "A-012", "claims": []}), encoding="utf-8")
    assert cli.main(["check", RUN]) == 2
    out = capsys.readouterr().out
    assert "Traceback" not in out and out.count("asa: ") == 3


@pytest.mark.parametrize("field,text", [("process", "'name'"), ("_t", "+00:00"), ("event_id", "E-"),
                                        ("signal.encoded_args", "True"), ("process.hash", "7c7c")])
def test_quote_needs_a_plain_field_the_tools_show(repo, field, text):
    run_dir = make_run(repo)
    edit_verdict(run_dir, lambda v: v["claims"][0].update(quotes=[{"event_id": "E-000103", "field": field, "text": text}]))
    assert kinds(repo, run_dir) == ["quote_mismatch"]


def test_check_refuses_a_linked_output_file(repo, repo_dir, monkeypatch, capsys, tmp_path):
    run_dir = make_run(repo)
    target = tmp_path / "elsewhere.json"
    target.write_text("{}", encoding="utf-8")
    try:
        (run_dir / "check.json").symlink_to(target)
    except OSError:
        pytest.skip("this account cannot create symlinks")
    monkeypatch.chdir(repo_dir)
    assert cli.main(["check", RUN]) == 2
    assert target.read_text(encoding="utf-8") == "{}"


def test_oversized_json_and_transcript_are_refused_unread(tmp_path, monkeypatch):
    """read_json / read_transcript stop at the record cap (32 MB, the audit trail's): bad input, exit 2, no huge read."""
    from asa import common
    from asa.checker import read_transcript
    from asa.common import UsageError, read_json

    monkeypatch.setattr(common, "MAX_RECORD_BYTES", 64, raising=False)
    big = tmp_path / "verdict.json"
    big.write_text(json.dumps({"x": "y" * 100}), encoding="utf-8")
    with pytest.raises(UsageError, match="too large"):
        read_json(big, "verdict.json")
    lines = tmp_path / "transcript.jsonl"
    lines.write_text("".join(json.dumps({"n": i}) + "\n" for i in range(20)), encoding="utf-8")
    with pytest.raises(UsageError, match="too large"):
        read_transcript(lines)
    small = tmp_path / "small.json"
    small.write_text('{"ok": 1}', encoding="utf-8")
    assert read_json(small, "small.json") == {"ok": 1}
    monkeypatch.setattr(common, "MAX_RECORD_BYTES", 1024)
    sep = tmp_path / "sep.jsonl"  # a line separator inside a string is not a line break (as when the file is iterated)
    sep.write_text(json.dumps({"t": "a b"}, ensure_ascii=False) + "\r\n" + json.dumps({"n": 2}) + "\n", encoding="utf-8")
    assert read_transcript(sep) == [{"t": "a b"}, {"n": 2}]


@pytest.mark.skipif(os.name == "nt", reason="file-size limit (RLIMIT_FSIZE) is POSIX only")
def test_write_json_never_leaves_a_half_written_file(tmp_path):
    """A write that fails part way (disk full, size limit) keeps the old file whole: temp file + os.replace, not
    truncate-then-write."""
    import resource
    import signal

    from asa.common import write_json

    path = tmp_path / "check.json"
    write_json(path, {"old": True})
    before = path.read_bytes()
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    old_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (64, hard))  # a write past 64 bytes fails with EFBIG
    try:
        with pytest.raises(OSError):
            write_json(path, {"new": "x" * 500})
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
        signal.signal(signal.SIGXFSZ, old_handler)
    assert path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["check.json"]  # no temp file left behind
    write_json(path, {"new": 1})
    assert json.loads(path.read_text(encoding="utf-8")) == {"new": 1} and path.read_bytes().endswith(b"}\n")
