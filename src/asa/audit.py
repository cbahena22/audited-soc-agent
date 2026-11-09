"""The audit trail: one append-only, hash-chained `audit.jsonl` per run folder, and the code that verifies it.

Each line is {seq, at, kind, actor, summary, data_sha256, prev_sha256, sha256}:
  kind         run_start | model_turn | tool_call | tool_result | verdict | check | intel | approval | run_end
  actor        agent | code | person:<name>
  data_sha256  SHA-256 of the canonical JSON of the record the line stands for (the trail keeps hashes and short
               summaries, never copies of tool output: transcript.jsonl holds those)
  prev_sha256  the previous line's sha256 (64 zeros on line 1)
  sha256       SHA-256 of the canonical line without `sha256`
Canonical JSON = sorted keys, no spaces, UTF-8, NaN / Infinity refused: the same bytes as `common.sha256_json` hashes.
Each line is stored in exactly that canonical form, so any changed byte breaks the chain.

`verify(run_dir)` checks the chain and then re-hashes the files the lines stand for: every transcript.jsonl line,
verdict.json, every approvals.jsonl line, and check.json / intel.json against the LAST check / intel line (both files
are rewritten when their command runs again). What it cannot see on its own: someone rewriting the whole chain, or
cutting lines off the end together with the files they stand for. Comparing the head hash and line count with a copy
kept elsewhere (`expected_head`, `expected_lines`) closes that gap; the README and trust.json carry them for the demo run.

Writers take an exclusive lock file (`audit.jsonl.lock`, O_CREAT | O_EXCL, stale after 30 s) for read -> verify ->
append, so two writers never interleave: the second waits, then refuses. The lock holds a random token; every removal
(a stale takeover, an owner's release) happens under a second O_EXCL file, the breaker, and an owner removes the lock
only while it still holds its token, so two waiters never both take one over and a slow writer never frees a new one.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .common import MAX_RECORD_BYTES, UsageError, clean_text, utc_now

TRAIL = "audit.jsonl"
GENESIS = "0" * 64
KINDS = ("run_start", "model_turn", "tool_call", "tool_result", "verdict", "check", "intel", "approval", "run_end")
NAME = r"[A-Za-z][A-Za-z .'-]{0,40}"  # a person's name or role, the same rule as `asa approve --as`
ACTOR = re.compile(rf"^(agent|code|person:{NAME})$")
AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FIELDS = ("seq", "at", "kind", "actor", "summary", "data_sha256", "prev_sha256", "sha256")
MAX_SUMMARY = 200
MAX_LINE_BYTES = 4096
MAX_TRAIL_BYTES = 4 * 1024 * 1024
LOCK_STALE_S = 30.0
LOCK_WAIT_S = 5.0
# Lines that stand for the agent loop, in transcript order; the post-run lines that may follow run_end.
LOOP_KINDS = ("model_turn", "tool_call", "tool_result")
AFTER_RUN = ("check", "intel", "approval")
FILE_RECORDS = {"check": "check.json", "intel": "intel.json"}


class AuditError(UsageError):
    """The trail cannot be written or does not verify: the command refuses (exit 2), nothing is assumed."""


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def canonical(obj: Any) -> bytes:
    """Sorted keys, no spaces, UTF-8; NaN and Infinity are refused (they have no JSON form)."""
    try:
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise AuditError(f"record cannot be hashed: {type(exc).__name__}") from None
    # surrogatepass: a lone surrogate from model input hashes instead of crashing (same rule as common.sha256_json)
    return text.encode("utf-8", "surrogatepass")


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def file_view(record: Any) -> Any:
    """What a check / intel line hashes: the record without its `run` path, so a copied run folder still verifies and
    a replay hashes the same whatever its run id."""
    return {k: v for k, v in record.items() if k != "run"} if isinstance(record, dict) else record


def _line_sha(line: dict) -> str:
    return digest({k: v for k, v in line.items() if k != "sha256"})


def _loads(raw: bytes | str) -> Any:
    return json.loads(raw, parse_constant=_no_constant, object_pairs_hook=_no_duplicates)


def _shape(line: Any) -> str | None:
    """Why one parsed line is malformed, or None."""
    if not isinstance(line, dict) or tuple(sorted(line)) != tuple(sorted(FIELDS)):
        return "not a trail line (wrong fields)"
    if not isinstance(line["seq"], int) or isinstance(line["seq"], bool):
        return "seq is not a number"
    if not isinstance(line["at"], str) or not AT.fullmatch(line["at"]):
        return "bad time"
    if line["kind"] not in KINDS:
        return "unknown kind"
    if not isinstance(line["actor"], str) or not ACTOR.fullmatch(line["actor"]):
        return "bad actor"
    if not isinstance(line["summary"], str) or len(line["summary"]) > MAX_SUMMARY:
        return "bad summary"
    for key in ("data_sha256", "prev_sha256", "sha256"):
        if not isinstance(line[key], str) or not HEX64.fullmatch(line[key]):
            return f"bad {key}"
    return None


def read_chain(path: Path) -> tuple[list[dict], int | None, str | None]:
    """(lines, first_bad_seq, reason): the lines that verify, then where and why the chain breaks (None, None if it holds).
    first_bad_seq is the seq the broken line has (or should have)."""
    if path.is_symlink() or not path.is_file():
        return [], None if not path.exists() else 1, "no audit trail (audit.jsonl)" if not path.exists() else "audit.jsonl is not a plain file"
    size = path.stat().st_size
    if size > MAX_TRAIL_BYTES:
        return [], 1, "audit.jsonl is too large"
    raw = path.read_bytes()
    if not raw:
        return [], 1, "audit.jsonl is empty"
    chunks = raw.split(b"\n")
    tail = chunks.pop()
    lines: list[dict] = []
    prev = GENESIS
    for i, chunk in enumerate(chunks, start=1):
        if len(chunk) > MAX_LINE_BYTES:
            return lines, i, "line too long"
        try:
            line = _loads(chunk.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return lines, i, "line is not valid JSON"
        why = _shape(line)
        if why:
            return lines, i, why
        if line["seq"] != i:
            return lines, i, f"seq {line['seq']} where {i} was expected (line removed, added or moved)"
        if line["prev_sha256"] != prev:
            return lines, i, "prev_sha256 does not match the line before (line removed, moved or replaced)"
        if canonical(line) != chunk:
            return lines, i, "line is not in canonical form (edited)"
        if _line_sha(line) != line["sha256"]:
            return lines, i, "sha256 does not match the line (edited)"
        lines.append(line)
        prev = line["sha256"]
    if tail:
        return lines, len(chunks) + 1, "last line is cut off (no newline)"
    return lines, None, None


def verify_chain(path: Path) -> tuple[bool, int | None, str | None]:
    lines, bad, why = read_chain(Path(path))
    return why is None, bad, why


def _trail_path(target: Path) -> tuple[Path, Path]:
    target = Path(target)
    if target.name == TRAIL and not target.is_dir():
        return target.parent, target
    return target, target / TRAIL


def _read_record(path: Path, what: str) -> tuple[bool, Any]:
    """(present, value) for a JSON file; a broken file is (True, AuditError)."""
    if not path.exists():
        return False, None
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECORD_BYTES:
            raise ValueError
        return True, _loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return True, AuditError(f"cannot read {what}")


def _read_lines(path: Path, what: str) -> list[Any] | AuditError:
    if not path.exists():
        return []
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECORD_BYTES:
            raise ValueError
        with path.open(encoding="utf-8") as f:
            return [_loads(line) for line in f if line.strip()]
    except (OSError, ValueError, RecursionError):
        return AuditError(f"cannot read {what}")


def expected_loop(transcript: list[Any]) -> list[tuple[str, str]]:
    """The (kind, data_sha256) pairs the agent loop writes for a transcript, in order."""
    out = []
    for line in transcript:
        kind = line.get("type") if isinstance(line, dict) else None
        if kind == "assistant":
            out.append(("model_turn", digest(line)))
        elif kind == "tool_result":
            out.append(("tool_call", digest(tool_call_record(line.get("tool_use_id"), line.get("name"), line.get("input")))))
            out.append(("tool_result", digest(line)))
        else:
            out.append(("?", "transcript line of unknown type"))
    return out


def tool_call_record(tool_use_id: Any, name: Any, args: Any) -> dict:
    return {"tool_use_id": tool_use_id, "name": name, "input": args}


def _order(lines: list[dict]) -> tuple[int | None, str | None]:
    """run_start first and once; loop lines, one verdict, one run_end; after run_end only check / intel / approval."""
    if not lines:
        return 1, "audit.jsonl is empty"
    if lines[0]["kind"] != "run_start":
        return 1, "the trail does not start with run_start"
    phase = "loop"
    for line in lines[1:]:
        kind, seq = line["kind"], line["seq"]
        if kind == "run_start":
            return seq, "a second run_start"
        if phase == "loop" and kind in LOOP_KINDS:
            continue
        if phase == "loop" and kind == "verdict":
            phase = "verdict"
            continue
        if phase == "verdict" and kind == "run_end":
            phase = "after"
            continue
        if phase == "after" and kind in AFTER_RUN:
            continue
        return seq, f"{kind} out of order"
    if phase != "after":
        return lines[-1]["seq"], "the run did not finish (no verdict and run_end)"
    return None, None


def verify(run_dir: Path, expected_head: str | None = None, expected_lines: int | None = None) -> tuple[bool, int | None, str | None]:
    """(ok, first_bad_seq, reason) for one run folder: the chain, the order of kinds, and every file the lines stand for.
    With an anchor (head hash and line count kept elsewhere) a cut-off tail or a rewritten chain is caught too."""
    if expected_lines is not None and (isinstance(expected_lines, bool) or not isinstance(expected_lines, int) or expected_lines < 1):
        raise AuditError("expected_lines: a whole number of lines, at least 1")
    if expected_head is not None and (not isinstance(expected_head, str) or not HEX64.fullmatch(expected_head)):
        raise AuditError("expected_head: 64 lower-case hex characters")
    run_dir, path = _trail_path(Path(run_dir))
    lines, bad, why = read_chain(path)
    if why:
        return False, bad, why
    if expected_lines is not None:
        if len(lines) < expected_lines:
            return False, len(lines) + 1, f"trail has {len(lines)} lines, the anchor says {expected_lines} (lines cut off the end)"
        if expected_head is not None and lines[expected_lines - 1]["sha256"] != expected_head:
            return False, expected_lines, "head hash differs from the anchor (chain rewritten)"
    elif expected_head is not None and lines[-1]["sha256"] != expected_head:
        return False, lines[-1]["seq"], "head hash differs from the anchor"
    bad, why = _order(lines)
    if why:
        return False, bad, why
    by_kind: dict[str, list[dict]] = {}
    for line in lines:
        by_kind.setdefault(line["kind"], []).append(line)
    run_end = by_kind["run_end"][0]["seq"]

    transcript = _read_lines(run_dir / "transcript.jsonl", "transcript.jsonl")
    if isinstance(transcript, AuditError):
        return False, 1, str(transcript)
    want = expected_loop(transcript)
    got = [line for line in lines if line["kind"] in LOOP_KINDS]
    for i, (kind, sha) in enumerate(want):
        if i >= len(got):
            return False, by_kind["verdict"][0]["seq"], f"transcript.jsonl has more lines than the trail (line {_transcript_line(want, i)})"
        if got[i]["kind"] != kind or got[i]["data_sha256"] != sha:
            return False, got[i]["seq"], f"transcript.jsonl line {_transcript_line(want, i)} differs from the trail"
    if len(got) > len(want):
        return False, got[len(want)]["seq"], "transcript.jsonl is missing lines the trail records"

    present, verdict = _read_record(run_dir / "verdict.json", "verdict.json")
    if isinstance(verdict, AuditError):
        return False, by_kind["verdict"][0]["seq"], str(verdict)
    if not present or digest(verdict) != by_kind["verdict"][0]["data_sha256"]:
        return False, by_kind["verdict"][0]["seq"], "verdict.json differs from the trail" if present else "verdict.json is missing"

    approvals = _read_lines(run_dir / "approvals.jsonl", "approvals.jsonl")
    if isinstance(approvals, AuditError):
        return False, run_end, str(approvals)
    recorded = by_kind.get("approval", [])
    for i, record in enumerate(approvals):
        if i >= len(recorded):
            return False, lines[-1]["seq"], f"approvals.jsonl line {i + 1} is not in the trail"
        if digest(record) != recorded[i]["data_sha256"]:
            return False, recorded[i]["seq"], f"approvals.jsonl line {i + 1} differs from the trail"
    if len(recorded) > len(approvals):
        return False, recorded[len(approvals)]["seq"], "approvals.jsonl is missing a line the trail records"

    for kind, name in FILE_RECORDS.items():
        present, record = _read_record(run_dir / name, name)
        noted = by_kind.get(kind, [])
        if isinstance(record, AuditError):
            return False, noted[-1]["seq"] if noted else run_end, str(record)
        if present and not noted:
            return False, lines[-1]["seq"], f"{name} is not in the trail"
        if noted and not present:
            return False, noted[-1]["seq"], f"{name} is missing"
        if present and digest(file_view(record)) != noted[-1]["data_sha256"]:
            return False, noted[-1]["seq"], f"{name} differs from the last {kind} line"
    return True, None, None


def _transcript_line(want: list[tuple[str, str]], index: int) -> int:
    """1-based transcript line number of the index-th expected loop line (a tool result line yields two)."""
    line, i = 0, 0
    while i <= index:
        line += 1
        i += 2 if want[i][0] == "tool_call" else 1
    return line


def head(run_dir: Path) -> tuple[int, str | None]:
    """(lines, head sha256) of a run's trail that verifies as a chain; (0, None) without one."""
    lines, _, why = read_chain(_trail_path(Path(run_dir))[1])
    if why or not lines:
        return 0, None
    return len(lines), lines[-1]["sha256"]


def now_at() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


_EXCL = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _create_token_file(path: Path) -> bytes:
    """Create `path` exclusively, holding a random token only this holder knows. Raises FileExistsError if it exists."""
    token = f"{os.getpid()} {secrets.token_hex(16)}".encode("ascii")
    fd = os.open(path, _EXCL, 0o600)
    try:
        os.write(fd, token)
    finally:
        os.close(fd)
    return token


def _read_token(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        return os.read(fd, 256)
    except OSError:
        return None
    finally:
        os.close(fd)


def _take_breaker(lock: Path) -> bytes | None:
    """The breaker (`audit.jsonl.lock.breaker`, O_EXCL) serialises every removal of the lock file: a stale takeover and
    an owner's release. Returns its token, or None when someone else holds it or it cannot be created (fail closed)."""
    breaker = lock.with_name(lock.name + ".breaker")
    try:
        return _create_token_file(breaker)
    except FileExistsError:
        try:  # a breaker left by a process that died in the few microseconds it holds one
            if time.time() - os.lstat(breaker).st_mtime > LOCK_STALE_S:
                os.unlink(breaker)
        except OSError:
            pass
        return None
    except OSError:  # e.g. a read-only run folder: no takeover, no removal
        return None


def _drop_breaker(lock: Path, token: bytes) -> None:
    breaker = lock.with_name(lock.name + ".breaker")
    try:
        if _read_token(breaker) == token:
            os.unlink(breaker)
    except OSError:  # gone already, or held open by a scanner (Windows sharing violation): it goes stale, fail closed
        pass


def _take_over_stale(lock: Path) -> bool:
    """Remove a lock left by a writer that died (older than LOCK_STALE_S), deciding under the breaker: no other process
    can remove or replace the lock while it is held, so the lock found stale here is the one removed. True if removed."""
    breaker = _take_breaker(lock)
    if breaker is None:
        return False
    try:
        if time.time() - os.lstat(lock).st_mtime <= LOCK_STALE_S:
            return False  # replaced by a live writer since the first look
        os.unlink(lock)
        return True
    except FileNotFoundError:
        return True  # gone: try to create it again
    except OSError:
        return False
    finally:
        _drop_breaker(lock, breaker)


def _release(lock: Path, token: bytes, wait: float) -> None:
    """Remove the lock only if it still holds our token (after a takeover it belongs to someone else, and a reused inode
    number proves nothing), under the breaker. If the breaker stays busy the lock is left to go stale."""
    deadline = time.monotonic() + wait
    while True:
        breaker = _take_breaker(lock)
        if breaker is not None:
            try:
                if _read_token(lock) == token:
                    os.unlink(lock)
            except OSError:  # gone already, or held open by a scanner/indexer (Windows sharing violation): the lock goes stale
                pass
            finally:
                _drop_breaker(lock, breaker)
            return
        if time.monotonic() >= deadline:
            return
        time.sleep(0.01)


@contextmanager
def _locked(path: Path, wait: float) -> Iterator[None]:
    lock = path.with_name(path.name + ".lock")
    deadline = time.monotonic() + wait
    while True:
        try:
            token = _create_token_file(lock)
            break
        except FileExistsError:
            try:
                age = time.time() - os.lstat(lock).st_mtime
            except FileNotFoundError:
                continue
            if age > LOCK_STALE_S and _take_over_stale(lock):  # a writer that died while holding it
                continue
        except OSError as exc:
            raise AuditError(f"cannot take audit.jsonl.lock ({type(exc).__name__}); nothing written") from None
        # busy, or a stale lock this process may not remove (breaker held, read-only folder): wait, then refuse
        if time.monotonic() >= deadline:
            raise AuditError("audit trail is busy (another writer holds audit.jsonl.lock); try again") from None
        time.sleep(0.05)
    try:
        yield
    finally:
        _release(lock, token, max(wait, LOCK_WAIT_S))


class Writer:
    """Appends to a trail whose chain verified when the lock was taken (see Trail.writer)."""

    def __init__(self, path: Path, lines: list[dict], fixed_clock: bool):
        self.path = path
        self.seq = len(lines)
        self.prev = lines[-1]["sha256"] if lines else GENESIS
        self.last_at = lines[-1]["at"] if lines else None
        self.fixed_clock = fixed_clock

    def append(self, kind: str, actor: str, summary: str, data: Any, at: str | None = None) -> dict:
        if kind not in KINDS:
            raise AuditError(f"unknown trail kind: {kind}")
        if not isinstance(actor, str) or not ACTOR.fullmatch(actor):
            raise AuditError("bad trail actor")
        if at is None:
            at = self.last_at if self.fixed_clock and self.last_at else now_at()
        if not AT.fullmatch(at):
            raise AuditError("bad trail time")
        if kind in FILE_RECORDS:  # check / intel: the file's record without its run path (what verify re-hashes)
            data = file_view(data)
        line = {"seq": self.seq + 1, "at": at, "kind": kind, "actor": actor,
                "summary": clean_text(summary)[:MAX_SUMMARY], "data_sha256": digest(data), "prev_sha256": self.prev}
        line["sha256"] = _line_sha(line)
        raw = canonical(line) + b"\n"
        if len(raw) > MAX_LINE_BYTES:
            raise AuditError("trail line too long")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o644)
        try:
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        self.seq, self.prev, self.last_at = line["seq"], line["sha256"], at
        return line


class Trail:
    """The trail of one run folder. `fixed_clock` (replays): a line without its own time takes the time of the line
    before it, so replaying a recording writes the same trail, byte for byte, on any machine."""

    def __init__(self, path: Path, fixed_clock: bool | None = None, wait: float = LOCK_WAIT_S):
        self.path = Path(path)
        self.fixed_clock = fixed_clock
        self.wait = wait

    @classmethod
    def of(cls, run_dir: Path, **kwargs: Any) -> "Trail":
        return cls(Path(run_dir) / TRAIL, **kwargs)

    def exists(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    def _fixed(self) -> bool:
        if self.fixed_clock is not None:
            return self.fixed_clock
        try:
            verdict = json.loads((self.path.parent / "verdict.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            return False
        return isinstance(verdict, dict) and verdict.get("replay_of") is not None

    @contextmanager
    def writer(self) -> Iterator[Writer]:
        """Lock, verify the chain as it is on disk, then hand out a writer. Refuses a chain that does not verify."""
        if self.path.is_symlink() or (self.path.exists() and not self.path.is_file()):
            raise AuditError("refusing to write audit.jsonl: not a plain file in the run folder")
        if self.path.parent.resolve() != self.path.resolve().parent:
            raise AuditError("refusing to write audit.jsonl: not a plain file in the run folder")
        with _locked(self.path, self.wait):
            lines: list[dict] = []
            if self.path.exists():
                lines, bad, why = read_chain(self.path)
                if why:
                    raise AuditError(f"audit trail does not verify at seq {bad}: {why}; nothing written")
            yield Writer(self.path, lines, self._fixed())

    def append(self, kind: str, actor: str, summary: str, data: Any, at: str | None = None) -> dict:
        with self.writer() as w:
            return w.append(kind, actor, summary, data, at)


def note_file(run_dir: Path, kind: str, record: Any, summary: str, write: Callable[[], Any] | None = None) -> dict | None:
    """Record a rewritten check.json / intel.json (`kind` check | intel) in the run's trail, if the run has one.
    A run folder without a trail (made before trails existed) gets none.

    With `write` (the call that writes the file), the file and its trail line are one step under the trail's lock, like
    an approval: a trail that does not verify refuses before anything is written, and two commands cannot leave the file
    from one and the last line from the other. Without it, call note_file right after the file is written."""
    if kind not in FILE_RECORDS:
        raise AuditError(f"not a file record kind: {kind}")
    trail = Trail.of(run_dir)
    if not trail.exists():
        if write is not None:
            write()
        return None
    with trail.writer() as w:
        if write is None:
            return w.append(kind, "code", summary, file_view(record))
        write()
        try:
            return w.append(kind, "code", summary, file_view(record))
        except (OSError, AuditError) as exc:
            why = str(exc) if isinstance(exc, AuditError) else type(exc).__name__
            raise AuditError(f"{FILE_RECORDS[kind]} written; trail append failed: {why}") from None


def require_writable(run_dir: Path) -> None:
    """Refuse before writing a file the trail must record, when the run has a trail that does not verify as a chain."""
    path = Path(run_dir) / TRAIL
    if path.exists() or path.is_symlink():
        ok, bad, why = verify_chain(path)
        if not ok:
            raise AuditError(f"audit trail does not verify at seq {bad}: {why}; nothing written")
