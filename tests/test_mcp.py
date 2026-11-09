import io
import json
import os
import subprocess
import sys
from pathlib import Path

import asa
from asa.mcp_server import MAX_LINE, serve

# The folder that holds the `asa` under test, absolute: the subprocess runs in another cwd, where a relative
# PYTHONPATH (e.g. PYTHONPATH=src) would point nowhere.
ASA_SRC = str(Path(asa.__file__).resolve().parents[1])


def rpc(rid, method, params=None):
    msg = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode() + b"\n"


def run_lines(repo, lines: list[bytes]) -> list[dict]:
    out = io.BytesIO()
    assert serve(repo, io.BytesIO(b"".join(lines)), out) == 0
    return [json.loads(x) for x in out.getvalue().splitlines()]


def test_subprocess_round_trip(repo_dir):
    lines = [rpc(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
             json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode() + b"\n",
             rpc(2, "tools/list"),
             rpc(3, "tools/call", {"name": "get_alert", "arguments": {"alert_id": "A-007"}})]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([ASA_SRC] + [p for p in [os.environ.get("PYTHONPATH")] if p])}
    proc = subprocess.run([sys.executable, "-m", "asa.cli", "mcp"], input=b"".join(lines), capture_output=True,
                          cwd=repo_dir, timeout=60, env=env)
    assert proc.returncode == 0, proc.stderr
    replies = [json.loads(x) for x in proc.stdout.splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3]  # the notification got no reply
    assert replies[0]["result"]["serverInfo"]["name"] == "asa"
    tools = replies[1]["result"]["tools"]
    assert sorted(t["name"] for t in tools) == ["get_alert", "host_timeline", "network_connections", "process_tree", "search_events"]
    assert all(t["annotations"]["readOnlyHint"] is True for t in tools)
    alert = json.loads(replies[2]["result"]["content"][0]["text"])["alert"]
    assert alert["alert_id"] == "A-007" and replies[2]["result"]["isError"] is False


def test_bad_json_then_next_line_served(repo):
    replies = run_lines(repo, [b"{not json\n", b"\xff\xfe\n", rpc(5, "ping")])
    assert [r["error"]["code"] for r in replies[:2]] == [-32700, -32700]
    assert replies[2] == {"jsonrpc": "2.0", "id": 5, "result": {}}


def test_not_a_request_unknown_method_bad_params(repo):
    replies = run_lines(repo, [b"[1, 2]\n", b'{"jsonrpc": "2.0", "id": 1}\n', b'"text"\n', rpc(2, "resources/list"),
                               b'{"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": [1]}\n',
                               b'{"jsonrpc": "2.0", "id": {"x": 1}, "method": "ping"}\n'])
    assert [r["error"]["code"] for r in replies] == [-32600, -32600, -32600, -32601, -32602, -32600]
    assert replies[1]["id"] == 1


def test_bad_args_are_tool_errors(repo):
    replies = run_lines(repo, [
        rpc(1, "tools/call", {"name": "get_alert", "arguments": {"alert_id": "../evals/answer_key.json"}}),
        rpc(2, "tools/call", {"name": "search_events", "arguments": {"host": "WS-03"}}),
        rpc(3, "tools/call", {"name": "get_alert", "arguments": "A-007"}),
        rpc(4, "tools/call", {"name": "read_file", "arguments": {}}),
    ])
    assert replies[0]["result"]["isError"] and "bad alert_id" in replies[0]["result"]["content"][0]["text"]
    assert replies[1]["result"]["isError"] and replies[2]["result"]["isError"]
    assert replies[3]["error"]["code"] == -32602


def test_oversized_line_refused_and_drained(repo):
    big = b'{"jsonrpc": "2.0", "id": 9, "method": "ping", "pad": "' + b"a" * (70 * 1024) + b'"}\n'
    replies = run_lines(repo, [big, rpc(10, "ping")])
    assert len(replies) == 2
    assert replies[0]["error"]["code"] == -32600 and "too long" in replies[0]["error"]["message"]
    assert replies[1] == {"jsonrpc": "2.0", "id": 10, "result": {}}


def test_line_at_the_limit_is_served(repo):
    head = b'{"jsonrpc": "2.0", "id": 11, "method": "ping", "pad": "'
    tail = b'"}\n'
    line = head + b"a" * (MAX_LINE - len(head) - len(tail)) + tail
    assert len(line) == MAX_LINE
    assert run_lines(repo, [line]) == [{"jsonrpc": "2.0", "id": 11, "result": {}}]


def test_garbage_never_crashes(repo):
    junk = [b"[" * 60000 + b"\n", b"\x00\x01\x02\n", b"null\n", b"{}\n", b'{"method": 5, "id": 1}\n', b'{"id": true, "method": "ping"}\n',
            b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": null}}\n', b"\n", b"   \n"]
    replies = run_lines(repo, junk + [rpc(99, "ping")])
    assert replies[-1] == {"jsonrpc": "2.0", "id": 99, "result": {}}
    assert all("error" in r for r in replies[:-1])


LONE = chr(0xD800)  # a lone UTF-16 surrogate: valid in a JSON escape, not encodable as UTF-8


def test_lone_surrogate_in_id_and_argument_key(repo):
    first = json.dumps({"jsonrpc": "2.0", "id": LONE, "method": "ping"}).encode() + b"\n"
    second = rpc(2, "tools/call", {"name": "get_alert", "arguments": {chr(0xDC00): 1}})
    replies = run_lines(repo, [first, second, rpc(3, "ping")])
    assert replies[0] == {"jsonrpc": "2.0", "id": LONE, "result": {}}
    assert replies[1]["result"]["isError"] is True
    assert replies[2] == {"jsonrpc": "2.0", "id": 3, "result": {}}
