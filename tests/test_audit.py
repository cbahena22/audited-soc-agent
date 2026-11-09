"""The audit trail: chain rules, tamper cases, the files it vouches for, the append lock and the CLI."""
import json
import math
import os
import threading
import time
import types

import pytest

from asa import audit, cli
from asa.actions import approve
from asa.agent import investigate
from asa.checker import check_run
from asa.common import sha256_json
from asa.llm import Budget, Ledger, LiveClient, ReplayClient
from fakes import FakeSDK, fixture_turns, install_recording
from test_checker import RUN, make_run


def kinds(run_dir):
    return [json.loads(x)["kind"] for x in (run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]


def raw_lines(run_dir):
    return (run_dir / "audit.jsonl").read_bytes().split(b"\n")[:-1]


def write_lines(run_dir, lines):
    (run_dir / "audit.jsonl").write_bytes(b"".join(line + b"\n" for line in lines))


def rehash(lines):
    """Rebuild a whole chain from edited lines (what someone rewriting the trail would do)."""
    out, prev = [], audit.GENESIS
    for seq, raw in enumerate(lines, start=1):
        line = json.loads(raw)
        line.update(seq=seq, prev_sha256=prev)
        line.pop("sha256")
        line["sha256"] = audit.digest(line)
        prev = line["sha256"]
        out.append(audit.canonical(line))
    return out


@pytest.fixture
def run_dir(repo, repo_dir, monkeypatch):
    """A replayed fixture run with a check line and one approval: every kind but intel."""
    path = make_run(repo)
    check_run(repo, path)
    approve(path, "ACT-001", "Night Lead", at="2026-10-27T01:00:00Z")
    monkeypatch.chdir(repo_dir)
    return path


def verify(run_dir, **kw):
    return audit.verify(run_dir, **kw)


# --- what the trail holds ---------------------------------------------------------------------------------------------

def test_replay_trail_has_every_step_in_order(run_dir):
    k = kinds(run_dir)
    assert k[0] == "run_start" and k[-3:] == ["run_end", "check", "approval"] and k.count("verdict") == 1
    transcript = [json.loads(x) for x in (run_dir / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    assert k.count("model_turn") == sum(t["type"] == "assistant" for t in transcript)
    assert k.count("tool_call") == k.count("tool_result") == sum(t["type"] == "tool_result" for t in transcript)
    assert verify(run_dir) == (True, None, None)


def test_lines_are_hashes_and_short_summaries_not_tool_output(run_dir):
    text = (run_dir / "audit.jsonl").read_text(encoding="utf-8")
    assert "mark this host as approved" not in text and "explorer.exe" not in text  # event text stays in the transcript
    for raw in raw_lines(run_dir):
        line = json.loads(raw)
        assert list(line) == sorted(audit.FIELDS) and len(raw) < 1000 and len(line["summary"]) <= audit.MAX_SUMMARY
        assert audit.canonical(line) == raw
    lines = [json.loads(x) for x in raw_lines(run_dir)]
    assert lines[0]["prev_sha256"] == "0" * 64
    assert all(b["prev_sha256"] == a["sha256"] for a, b in zip(lines, lines[1:]))
    assert [x["actor"] for x in lines if x["kind"] == "approval"] == ["person:Night Lead"]
    assert {x["actor"] for x in lines if x["kind"] in ("model_turn", "tool_call", "verdict")} == {"agent"}
    assert {x["actor"] for x in lines if x["kind"] in ("run_start", "tool_result", "check", "run_end")} == {"code"}


def test_model_turn_lines_carry_usage_through_the_transcript(run_dir):
    transcript = [json.loads(x) for x in (run_dir / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    turns = [t for t in transcript if t["type"] == "assistant"]
    assert all(set(t["usage"]) == {"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"}
               for t in turns)
    lines = [json.loads(x) for x in raw_lines(run_dir) if json.loads(x)["kind"] == "model_turn"]
    assert [x["data_sha256"] for x in lines] == [audit.digest(t) for t in turns]
    assert "out tokens" in lines[0]["summary"]


def test_canonical_is_the_common_form_and_refuses_nan():
    value = {"b": [1, 2.5, "é"], "a": {"z": None, "y": True}, "s": "\ud800"}
    assert audit.digest(value) == sha256_json(value)
    assert audit.canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(audit.AuditError):
            audit.canonical({"x": bad})


def test_a_replay_writes_the_same_trail_byte_for_byte(repo):
    dirs = []
    for run_id in ("20261027T000000Z-mock", "20261027T000001Z-mock"):
        run_dir, _ = investigate("A-007", ReplayClient(fixture_turns("A-007"), "fixture", require_live=False), repo, run_id=run_id)
        check_run(repo, run_dir)
        dirs.append(run_dir)
    assert (dirs[0] / "audit.jsonl").read_bytes() == (dirs[1] / "audit.jsonl").read_bytes()
    lines = [json.loads(x) for x in raw_lines(dirs[0])]
    assert {x["at"] for x in lines} == {"2026-10-27T00:00:00Z"}  # the recording's clock, not the replay's


def test_run_start_hashes_the_recording_files(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir, alerts=("A-007",))
    monkeypatch.chdir(repo_dir)
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 0
    rec = repo_dir / "evals" / "recorded" / "live-20261027" / "A-007"
    client = ReplayClient.from_dir(rec, "live-20261027")
    assert client.source == {"turns_sha256": sha256_json(client.turns), "complete_sha256": sha256_json(client.complete)}
    run_dir = next((repo_dir / "out" / "runs").iterdir()) / "A-007"
    first = json.loads(raw_lines(run_dir)[0])
    start = {"alert_id": "A-007", "mode": "replay", "model": client.model, "effort": client.effort,
             "replay_of": client.replay_of, "recording": client.source, "recording_name": None, "budget_usd": None}
    assert first["data_sha256"] == audit.digest(start)
    assert "replay of live-20261027" in first["summary"]


def test_live_trail_uses_the_real_clock_and_names_the_budget(repo, repo_dir):
    turns = fixture_turns("A-012")
    sdk = FakeSDK([t["response"] for t in turns])
    client = LiveClient(sdk, "claude-sonnet-5-5", "high", Budget(1.0, Ledger(repo_dir / "out" / "ledger" / "t.jsonl")))
    run_dir, _ = investigate("A-012", client, repo, run_id="20261027T000000Z-live")
    lines = [json.loads(x) for x in raw_lines(run_dir)]
    assert lines[0]["summary"].endswith("budget $1.00") and lines[0]["at"] != "2026-10-27T00:00:00Z"
    assert verify(run_dir) == (True, None, None)


def test_a_run_folder_without_a_trail_gets_none_and_does_not_verify(repo, repo_dir):
    run_dir = make_run(repo)
    (run_dir / "audit.jsonl").unlink()
    check_run(repo, run_dir)
    approve(run_dir, "ACT-001", "Night Lead")
    assert not (run_dir / "audit.jsonl").exists()
    assert verify(run_dir) == (False, None, "no audit trail (audit.jsonl)")


# --- tamper cases: the chain ------------------------------------------------------------------------------------------

def _edit_byte(lines):
    lines[4] = lines[4].replace(b'"summary":"', b'"summary":"X', 1)
    return lines, 5


def _delete(lines):
    del lines[3]
    return lines, 4


def _reorder(lines):
    lines[3], lines[4] = lines[4], lines[3]
    return lines, 4


def _duplicate(lines):
    lines.insert(3, lines[2])
    return lines, 4


def _forged_genesis(lines):
    start = json.loads(lines[0])
    start.pop("sha256")
    start["summary"] = "start A-007: something else"
    start["sha256"] = audit.digest(start)
    lines[0] = audit.canonical(start)  # a valid line 1 on its own, but line 2 no longer chains to it
    return lines, 2


def _second_genesis(lines):
    line = json.loads(lines[5])
    line.update(prev_sha256=audit.GENESIS)
    line.pop("sha256")
    line["sha256"] = audit.digest(line)
    lines[5] = audit.canonical(line)
    return lines, 6


def _whitespace(lines):
    lines[2] = lines[2].replace(b'","', b'", "', 1)
    return lines, 3


def _cut_line(lines):
    return lines, None  # handled below: no final newline


@pytest.mark.parametrize("tamper", [_edit_byte, _delete, _reorder, _duplicate, _forged_genesis, _second_genesis, _whitespace],
                         ids=lambda f: f.__name__.strip("_"))
def test_chain_tamper_fails_at_the_right_seq(run_dir, tamper):
    lines, seq = tamper(raw_lines(run_dir))
    write_lines(run_dir, lines)
    ok, bad, why = verify(run_dir)
    assert (ok, bad) == (False, seq), why


def test_a_cut_off_last_line_fails(run_dir):
    data = (run_dir / "audit.jsonl").read_bytes()
    (run_dir / "audit.jsonl").write_bytes(data[:-20])
    ok, bad, why = verify(run_dir)
    assert not ok and bad == len(data.split(b"\n")) - 1 and "cut off" in why


def test_a_trail_that_is_not_json_or_has_extra_fields_fails(run_dir):
    lines = raw_lines(run_dir)
    write_lines(run_dir, lines[:2] + [b'{"seq": NaN}'] + lines[3:])
    assert verify(run_dir)[:2] == (False, 3)
    line = json.loads(lines[2])
    line["extra"] = 1
    write_lines(run_dir, lines[:2] + [audit.canonical(line)] + lines[3:])
    assert verify(run_dir)[:2] == (False, 3)


def test_order_rules(run_dir):
    lines = raw_lines(run_dir)
    k = kinds(run_dir)
    # move the check line before run_end and re-chain it: the chain holds, the order does not
    i, j = k.index("check"), k.index("run_end")
    moved = lines[:j] + [lines[i], lines[j]] + lines[i + 1:]
    write_lines(run_dir, rehash(moved))
    ok, bad, why = verify(run_dir)
    assert (ok, bad) == (False, j + 1) and "out of order" in why
    write_lines(run_dir, rehash(lines[:j]))  # no run_end: the run did not finish
    ok, bad, why = verify(run_dir)
    assert not ok and "did not finish" in why


def test_tail_truncation_and_a_rewritten_chain_need_the_anchor(run_dir):
    n, head = audit.head(run_dir)
    assert verify(run_dir, expected_head=head, expected_lines=n) == (True, None, None)
    # cut the approval line off together with approvals.jsonl: the chain and the files still agree
    write_lines(run_dir, raw_lines(run_dir)[:-1])
    (run_dir / "approvals.jsonl").unlink()
    assert verify(run_dir) == (True, None, None)
    ok, bad, why = verify(run_dir, expected_head=head, expected_lines=n)
    assert (ok, bad) == (False, n) and "cut off" in why
    # rewrite the whole chain over an edited verdict: only the anchor catches it
    path = run_dir / "verdict.json"
    verdict = json.loads(path.read_text(encoding="utf-8"))
    verdict["verdict"] = "benign"
    path.write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")
    lines = raw_lines(run_dir)
    k = kinds(run_dir)
    v = json.loads(lines[k.index("verdict")])
    v["data_sha256"] = audit.digest(verdict)
    lines[k.index("verdict")] = audit.canonical(v)
    write_lines(run_dir, rehash(lines))
    assert verify(run_dir) == (True, None, None)
    ok, _, why = verify(run_dir, expected_head=head, expected_lines=n - 1)
    assert not ok and "anchor" in why


# --- tamper cases: the files the trail vouches for --------------------------------------------------------------------

def _seq_of(run_dir, kind, last=False):
    seqs = [i + 1 for i, k in enumerate(kinds(run_dir)) if k == kind]
    return seqs[-1] if last else seqs[0]


def test_an_edited_verdict_fails_at_the_verdict_line(run_dir):
    path = run_dir / "verdict.json"
    path.write_text(path.read_text(encoding="utf-8").replace('"confidence": "high"', '"confidence": "low"'), encoding="utf-8")
    ok, bad, why = verify(run_dir)
    assert (ok, bad, why) == (False, _seq_of(run_dir, "verdict"), "verdict.json differs from the trail")


def test_an_edited_transcript_line_fails_at_its_line(run_dir):
    path = run_dir / "transcript.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    k = kinds(run_dir)
    lines[1] = lines[1].replace("E-000103", "E-000199", 1)  # the first tool result
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad, why = verify(run_dir)
    assert (ok, bad) == (False, k.index("tool_result") + 1) and "line 2" in why


def test_a_removed_transcript_line_fails(run_dir):
    path = run_dir / "transcript.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    ok, _, why = verify(run_dir)
    assert not ok and "transcript.jsonl" in why


def test_an_edited_approval_and_an_unrecorded_approval_fail(run_dir):
    path = run_dir / "approvals.jsonl"
    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace("Night Lead", "Day Lead"), encoding="utf-8")
    assert verify(run_dir)[:2] == (False, _seq_of(run_dir, "approval"))
    path.write_text(original + json.dumps({"id": "ACT-002", "by": "Someone", "at": "2026-10-27T02:00:00Z",
                                           "status": "approved (dry run, not sent)"}) + "\n", encoding="utf-8")
    ok, _, why = verify(run_dir)
    assert not ok and "approvals.jsonl line 2 is not in the trail" == why


def test_check_json_is_compared_with_the_last_check_line(repo, run_dir):
    path = run_dir / "check.json"
    check = json.loads(path.read_text(encoding="utf-8"))
    check["findings"] = []
    check["claims"] = 99
    path.write_text(json.dumps(check), encoding="utf-8")
    assert verify(run_dir)[:2] == (False, _seq_of(run_dir, "check", last=True))
    check_run(repo, run_dir, use_key=True)  # a rerun rewrites check.json and adds a new check line
    assert kinds(run_dir).count("check") == 2 and verify(run_dir) == (True, None, None)
    path.unlink()
    assert verify(run_dir)[2] == "check.json is missing"


def test_check_json_is_written_under_the_trail_lock(repo, run_dir, monkeypatch):
    """check.json and its check line are one step under one lock (like approve): a second `asa check` cannot slip its
    file in between, leaving check.json from one run and the last check line from the other."""
    from asa import checker

    real = checker.write_json
    held = []

    def write_json(path, value):
        if path.name == "check.json":
            held.append((run_dir / "audit.jsonl.lock").exists())
        return real(path, value)

    monkeypatch.setattr(checker, "write_json", write_json)
    check_run(repo, run_dir, use_key=True)
    assert held == [True] and verify(run_dir) == (True, None, None)


def test_note_file_refuses_before_writing_when_the_trail_is_broken(run_dir):
    lines = raw_lines(run_dir)
    write_lines(run_dir, lines[:2] + lines[3:])  # a line removed
    wrote = []
    with pytest.raises(audit.AuditError, match="nothing written"):
        audit.note_file(run_dir, "intel", {"alert_id": "A-007"}, "intel", write=lambda: wrote.append(1))
    assert wrote == []


def test_an_intel_file_must_be_in_the_trail(run_dir):
    record = {"run": RUN, "alert_id": "A-007", "source": "fixtures", "indicators": []}
    (run_dir / "intel.json").write_text(json.dumps(record), encoding="utf-8")
    assert verify(run_dir)[2] == "intel.json is not in the trail"
    audit.note_file(run_dir, "intel", record, "intel: 0 indicators")
    assert verify(run_dir) == (True, None, None)
    record["indicators"] = [{"type": "ip", "value": "198.51.100.23", "verdict": "clear"}]
    (run_dir / "intel.json").write_text(json.dumps(record), encoding="utf-8")
    assert verify(run_dir)[2] == "intel.json differs from the last intel line"


def test_the_run_path_is_not_part_of_a_file_record(run_dir):
    path = run_dir / "check.json"
    check = json.loads(path.read_text(encoding="utf-8"))
    check["run"] = "out/runs/20991231T000000Z-mock/A-007"
    path.write_text(json.dumps(check), encoding="utf-8")
    assert verify(run_dir) == (True, None, None)


# --- writers refuse a broken chain ------------------------------------------------------------------------------------

def test_writers_refuse_a_chain_that_does_not_verify(repo, run_dir, capsys):
    lines, _ = _delete(raw_lines(run_dir))
    write_lines(run_dir, lines)
    before = (run_dir / "check.json").read_bytes()
    assert cli.main(["check", RUN]) == 2
    assert "audit trail does not verify at seq 4" in capsys.readouterr().out
    assert (run_dir / "check.json").read_bytes() == before
    approvals = (run_dir / "approvals.jsonl").read_bytes()
    assert cli.main(["approve", "ACT-002", "--run", RUN, "--as", "Night Lead"]) == 2
    assert (run_dir / "approvals.jsonl").read_bytes() == approvals
    with pytest.raises(audit.AuditError):
        audit.Trail.of(run_dir).append("check", "code", "x", {})


def test_writer_refuses_a_linked_trail(run_dir, tmp_path):
    target = tmp_path / "elsewhere.jsonl"
    target.write_bytes((run_dir / "audit.jsonl").read_bytes())
    (run_dir / "audit.jsonl").unlink()
    try:
        (run_dir / "audit.jsonl").symlink_to(target)
    except OSError:
        pytest.skip("no symlinks here")
    with pytest.raises(audit.AuditError, match="not a plain file"):
        audit.Trail.of(run_dir).append("check", "code", "x", {})
    assert verify(run_dir)[0] is False


def test_bad_kind_actor_and_time_are_refused(run_dir):
    trail = audit.Trail.of(run_dir)
    for kind, actor, at in (("delete", "code", None), ("check", "person:", None), ("check", "root", None),
                            ("check", "code", "yesterday")):
        with pytest.raises(audit.AuditError):
            trail.append(kind, actor, "x", {}, at=at)
    assert verify(run_dir) == (True, None, None)


def test_summaries_are_cleaned_and_capped(run_dir):
    line = audit.Trail.of(run_dir).append("check", "code", "a\x1b[31mred‮" + "x" * 500, {})
    assert "\x1b" not in line["summary"] and "‮" not in line["summary"] and len(line["summary"]) == audit.MAX_SUMMARY


# --- the append lock --------------------------------------------------------------------------------------------------

def test_a_held_lock_makes_the_second_writer_refuse(run_dir):
    lock = run_dir / "audit.jsonl.lock"
    lock.write_text("1", encoding="utf-8")
    with pytest.raises(audit.AuditError, match="busy"):
        audit.Trail.of(run_dir, wait=0.2).append("check", "code", "x", {})
    assert lock.exists() and verify(run_dir) == (True, None, None)


def test_a_stale_lock_is_taken_over(run_dir):
    lock = run_dir / "audit.jsonl.lock"
    lock.write_text("1", encoding="utf-8")
    old = time.time() - audit.LOCK_STALE_S - 5
    os.utime(lock, (old, old))
    n = audit.head(run_dir)[0]
    audit.Trail.of(run_dir, wait=0.2).append("intel", "code", "x", {})
    assert audit.head(run_dir)[0] == n + 1 and not lock.exists()


def test_a_stale_lock_replaced_by_another_waiter_is_not_taken_twice(run_dir, monkeypatch):
    """Two waiters see the same stale lock; the first replaces it with its own fresh lock before the second acts.
    The second must not delete that fresh lock (both would then hold it): it waits and refuses."""
    lock = run_dir / "audit.jsonl.lock"
    lock.write_text("1", encoding="utf-8")
    old = time.time() - audit.LOCK_STALE_S - 5
    os.utime(lock, (old, old))
    real_lstat = os.lstat
    swapped = []

    def lstat(path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == os.fspath(lock) and not swapped:  # the other waiter takes over right after our look
            swapped.append(True)
            os.unlink(lock)
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, b"other-waiter")
            os.close(fd)
        return result

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(audit.AuditError, match="busy"):
        audit.Trail.of(run_dir, wait=0.3).append("intel", "code", "x", {})
    monkeypatch.undo()
    assert swapped and lock.read_bytes() == b"other-waiter"  # the fresh lock is still there, untouched
    assert sorted(p.name for p in run_dir.iterdir() if p.name.startswith("audit.jsonl.lock")) == ["audit.jsonl.lock"]


def test_a_writer_releases_only_its_own_lock(run_dir):
    """A writer that held the lock past the stale age (taken over meanwhile) must not delete the new holder's lock."""
    lock = run_dir / "audit.jsonl.lock"
    with audit.Trail.of(run_dir).writer():
        os.unlink(lock)  # what a takeover does to it
        lock.write_bytes(b"new-holder")
    assert lock.read_bytes() == b"new-holder"


def test_release_does_not_trust_a_reused_inode_number(run_dir, monkeypatch):
    """ext4 can hand the new holder's lock the SAME inode number as the one a slow writer created: release must compare
    the lock's content (its token), not (dev, inode). Here lstat reports the old identity for the new file."""
    lock = run_dir / "audit.jsonl.lock"
    real_lstat = os.lstat
    with audit.Trail.of(run_dir).writer():
        old = real_lstat(lock)
        os.unlink(lock)  # a takeover, then a new holder whose lock gets the same inode number
        lock.write_bytes(b"new-holder")

        def lstat(path, *args, **kwargs):
            st = real_lstat(path, *args, **kwargs)
            if os.fspath(path) == os.fspath(lock):
                return types.SimpleNamespace(st_dev=old.st_dev, st_ino=old.st_ino, st_mtime=st.st_mtime,
                                             st_mtime_ns=st.st_mtime_ns)
            return st

        monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.undo()
    assert lock.read_bytes() == b"new-holder"


def _stale_lock(run_dir):
    lock = run_dir / "audit.jsonl.lock"
    lock.write_text("1", encoding="utf-8")
    old = time.time() - audit.LOCK_STALE_S - 5
    os.utime(lock, (old, old))
    return lock


def _finishes(fn, seconds=5.0):
    """Run fn in a daemon thread; (finished in time, exception or None). A hung lock loop must not hang the suite."""
    out = []
    t = threading.Thread(target=lambda: out.append(_catch(fn)), daemon=True)
    t.start()
    t.join(seconds)
    return (not t.is_alive()), (out[0] if out else None)


def _catch(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - the test inspects it
        return exc
    return None


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs POSIX permissions, not root")
def test_a_stale_lock_that_cannot_be_removed_waits_then_refuses(run_dir):
    """A read-only run folder: the stale lock cannot be taken over. The writer must still honour its wait and refuse,
    not spin forever."""
    lock = _stale_lock(run_dir)
    os.chmod(run_dir, 0o555)
    try:
        done, exc = _finishes(lambda: audit.Trail.of(run_dir, wait=0.3).append("intel", "code", "x", {}))
    finally:
        os.chmod(run_dir, 0o755)
    assert done, "the lock loop did not return"
    assert isinstance(exc, audit.AuditError) and "busy" in str(exc)
    assert lock.read_text(encoding="utf-8") == "1"


def test_a_takeover_needs_the_breaker(run_dir):
    """Every removal of the lock happens under the breaker: while another process holds it, a stale lock stays."""
    lock = _stale_lock(run_dir)
    breaker = run_dir / "audit.jsonl.lock.breaker"
    breaker.write_bytes(b"other process")
    done, exc = _finishes(lambda: audit.Trail.of(run_dir, wait=0.3).append("intel", "code", "x", {}))
    assert done and isinstance(exc, audit.AuditError) and "busy" in str(exc)
    assert lock.read_text(encoding="utf-8") == "1" and breaker.read_bytes() == b"other process"
    breaker.unlink()
    n = audit.head(run_dir)[0]
    audit.Trail.of(run_dir, wait=0.3).append("intel", "code", "x", {})
    assert audit.head(run_dir)[0] == n + 1
    assert sorted(p.name for p in run_dir.iterdir() if p.name.startswith("audit.jsonl.lock")) == []


def _unlink_denied(monkeypatch, *names):
    """Make os.unlink raise PermissionError for the named files (a Windows sharing violation from an AV scanner or indexer)."""
    real = os.unlink

    def unlink(path, *args, **kwargs):
        if os.path.basename(os.fspath(path)) in names:
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)


def test_release_survives_a_sharing_violation_and_leaves_the_lock_to_go_stale(run_dir, monkeypatch):
    """The lock cannot be unlinked on release: no exception escapes the write that already succeeded, the lock stays
    (fail closed: the next writer waits, then takes it over once stale) and the breaker is not left behind."""
    lock = run_dir / "audit.jsonl.lock"
    n = audit.head(run_dir)[0]
    with monkeypatch.context() as m:
        _unlink_denied(m, "audit.jsonl.lock")
        audit.Trail.of(run_dir, wait=0.2).append("intel", "code", "x", {})
    assert audit.head(run_dir)[0] == n + 1
    assert lock.exists() and not (run_dir / "audit.jsonl.lock.breaker").exists()
    with pytest.raises(audit.AuditError, match="busy"):  # fail closed while it is fresh
        audit.Trail.of(run_dir, wait=0.2).append("intel", "code", "y", {})
    old = time.time() - audit.LOCK_STALE_S - 5
    os.utime(lock, (old, old))
    audit.Trail.of(run_dir, wait=0.2).append("intel", "code", "z", {})  # stale: taken over, as after a crash
    assert audit.head(run_dir)[0] == n + 2


def test_a_breaker_that_cannot_be_removed_does_not_raise_and_goes_stale(run_dir, monkeypatch):
    """_drop_breaker hits a sharing violation: no exception, the breaker stays and blocks takeovers until it is stale,
    and a stale breaker is cleared by the next taker."""
    lock = run_dir / "audit.jsonl.lock"
    breaker = run_dir / "audit.jsonl.lock.breaker"
    token = audit._take_breaker(lock)
    assert token is not None and breaker.exists()
    with monkeypatch.context() as m:
        _unlink_denied(m, "audit.jsonl.lock.breaker")
        audit._drop_breaker(lock, token)  # must not raise
    assert breaker.exists() and audit._take_breaker(lock) is None  # fail closed: nobody takes over while it stands
    old = time.time() - audit.LOCK_STALE_S - 5
    os.utime(breaker, (old, old))
    assert audit._take_breaker(lock) is None  # this call clears the stale one ...
    token = audit._take_breaker(lock)
    assert token is not None  # ... and the next can take it
    audit._drop_breaker(lock, token)
    assert not breaker.exists()


def test_no_hard_links_does_not_lose_a_fresh_lock(run_dir, monkeypatch):
    """Where hard links are not supported (FAT / exFAT), a racing takeover must not drop a live writer's fresh lock."""
    lock = _stale_lock(run_dir)
    real_lstat = os.lstat
    swapped = []

    def no_link(*args, **kwargs):
        raise OSError("hard links not supported")

    def lstat(path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == os.fspath(lock) and not swapped:  # a live writer replaces it right after our look
            swapped.append(True)
            os.unlink(lock)
            lock.write_bytes(b"live-writer")
        return result

    monkeypatch.setattr(os, "link", no_link, raising=False)
    monkeypatch.setattr(os, "lstat", lstat)
    done, exc = _finishes(lambda: audit.Trail.of(run_dir, wait=0.3).append("intel", "code", "x", {}))
    monkeypatch.undo()
    assert done and isinstance(exc, audit.AuditError) and "busy" in str(exc)
    assert lock.read_bytes() == b"live-writer"


def test_two_writers_the_second_waits_for_the_first(run_dir):
    entered, release = threading.Event(), threading.Event()
    seqs = []

    def first():
        with audit.Trail.of(run_dir).writer() as w:
            entered.set()
            release.wait(5)
            seqs.append(("first", w.append("intel", "code", "first", {"n": 1})["seq"]))

    t = threading.Thread(target=first)
    t.start()
    entered.wait(5)
    timer = threading.Timer(0.3, release.set)
    timer.start()
    seqs.append(("second", audit.Trail.of(run_dir, wait=5).append("intel", "code", "second", {"n": 2})["seq"]))
    t.join(5)
    n = audit.head(run_dir)[0]
    assert seqs == [("first", n - 1), ("second", n)]
    lines = [json.loads(x) for x in raw_lines(run_dir)]
    assert [x["summary"] for x in lines[-2:]] == ["first", "second"]
    assert audit.verify_chain(run_dir / "audit.jsonl") == (True, None, None)


# --- the CLI ----------------------------------------------------------------------------------------------------------

def test_cli_verify_pass_and_fail(run_dir, capsys):
    assert cli.main(["audit", "verify", RUN]) == 0
    out = capsys.readouterr().out
    n, head = audit.head(run_dir)
    assert out.strip() == f"PASS {RUN}: {n} lines, head {head}"
    assert cli.main(["audit", "verify", RUN, "--head", head, "--lines", str(n)]) == 0
    assert cli.main(["audit", "verify", RUN, "--head", "0" * 64, "--lines", str(n)]) == 1
    capsys.readouterr()
    lines, seq = _edit_byte(raw_lines(run_dir))
    write_lines(run_dir, lines)
    assert cli.main(["audit", "verify", RUN]) == 1
    assert capsys.readouterr().out.startswith(f"FAIL {RUN} at seq {seq}: ")


@pytest.mark.parametrize("argv", [["audit", "verify", "out/runs/x/A-007"], ["audit", "verify", "../outside"],
                                  ["audit", "verify", RUN, "--head", "abc", "--lines", "3"],
                                  ["audit", "verify", RUN, "--head", "0" * 64]])
def test_cli_verify_bad_input_exits_2(run_dir, capsys, argv):
    try:
        code = cli.main(argv)
    except SystemExit as exc:  # argparse refuses a malformed --head itself
        code = exc.code
    assert code == 2


def test_anchor_arguments_are_checked(run_dir):
    for kw in ({"expected_lines": 0}, {"expected_lines": True}, {"expected_head": "XYZ"}):
        with pytest.raises(audit.AuditError):
            verify(run_dir, **kw)


def test_run_level_verify_skips_linked_alert_folders(run_dir, repo_dir, tmp_path, capsys):
    outside = tmp_path / "A-099"
    outside.mkdir()
    try:
        (run_dir.parent / "A-099").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("no symlinks here")
    assert cli.main(["audit", "verify", run_dir.parent.relative_to(repo_dir).as_posix()]) == 0
    out = capsys.readouterr().out
    n, head = audit.head(run_dir)
    assert "A-099" not in out and out.strip() == f"PASS {RUN}: {n} lines, head {head}"


def test_the_intel_hook_signature_used_by_the_intel_step(run_dir):
    """`Trail(path).append("intel", "code", summary, record)` with the full record (run path included) verifies."""
    record = {"run": RUN, "alert_id": "A-007", "source": "fixtures", "indicators": []}
    (run_dir / "intel.json").write_text(json.dumps(record), encoding="utf-8")
    audit.Trail(run_dir / "audit.jsonl").append("intel", "code", "intel: 0 indicators", record)
    assert verify(run_dir) == (True, None, None)
    record["source"] = "cache"  # a rerun rewrites intel.json and adds a line: only the last intel line counts
    (run_dir / "intel.json").write_text(json.dumps(record), encoding="utf-8")
    audit.Trail(run_dir / "audit.jsonl").append("intel", "code", "intel: rerun", record)
    assert kinds(run_dir).count("intel") == 2 and verify(run_dir) == (True, None, None)


def test_investigate_all_replays_every_alert_into_one_run(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["investigate", "--all", "--mock"]) == 0
    out = capsys.readouterr().out
    [run] = list((repo_dir / "out" / "runs").iterdir())
    assert sorted(p.name for p in run.iterdir()) == ["A-007", "A-012", "A-021"]
    assert f"replayed 3 of 3 alerts into out/runs/{run.name}" in out
    assert cli.main(["audit", "verify", f"out/runs/{run.name}"]) == 0
    assert capsys.readouterr().out.strip().endswith("3 of 3 trails verify")


@pytest.mark.parametrize("argv", [["investigate", "--all", "--live", "--budget", "1"], ["investigate", "--all", "--mock", "--budget", "1"]])
def test_investigate_all_is_mock_only(repo_dir, monkeypatch, capsys, argv):
    install_recording(repo_dir)
    monkeypatch.chdir(repo_dir)
    assert cli.main(argv) == 2
    assert not (repo_dir / "out" / "runs").exists()


def test_investigate_all_marks_a_missing_recording_incomplete(repo_dir, monkeypatch, capsys):
    install_recording(repo_dir, alerts=("A-007", "A-012"))
    monkeypatch.chdir(repo_dir)
    assert cli.main(["investigate", "--all", "--mock"]) == 1
    out = capsys.readouterr().out
    assert "A-021: failed" in out and "(INCOMPLETE)" in out
