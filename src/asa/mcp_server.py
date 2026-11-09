"""A stdio MCP server with no SDK: JSON-RPC 2.0, one message per line, the same five read-only tools as the agent.

No network listener. Lines longer than 64 KiB are refused (and the rest of the line is drained). Bad input gets a
JSON-RPC error and the loop carries on; it never crashes on input.
"""
from __future__ import annotations

import json
import sys
from typing import Any, BinaryIO

from . import __version__
from .common import Repo, UsageError
from .tools import TOOL_ARGS, TOOL_SCHEMAS, Dataset, input_schema

MAX_LINE = 65536
PROTOCOL_VERSION = "2025-11-25"


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def tool_list() -> list[dict]:
    return [{"name": name, "description": TOOL_SCHEMAS[name]["description"], "inputSchema": input_schema(name),
             "annotations": {"readOnlyHint": True}} for name in TOOL_ARGS]


def handle(method: str, params: dict, data: Dataset) -> dict:
    """The JSON-RPC method table (pattern adapted from earlier code by the author; server name and tools are new)."""
    if method == "initialize":
        return {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                "serverInfo": {"name": "asa", "version": __version__}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": tool_list()}
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments")
        if name not in TOOL_ARGS:
            raise RpcError(-32602, "unknown tool")
        try:
            result = data.call(name, args if args is not None else {})
        except UsageError as exc:  # bad arguments are a tool error, not a protocol error
            return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}], "isError": False}
    raise RpcError(-32601, "Method not found")


def respond(line: bytes, data: Dataset) -> dict | None:
    """One input line -> one reply (None for a notification)."""
    try:
        msg = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
    if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
        rid = msg.get("id") if isinstance(msg, dict) and isinstance(msg.get("id"), (str, int)) else None
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": "Invalid Request"}}
    if "id" not in msg:
        return None  # a notification (e.g. notifications/initialized) is never answered
    rid = msg["id"]
    if not isinstance(rid, (str, int)) or isinstance(rid, bool):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    params = msg.get("params") or {}
    if not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "params must be an object"}}
    try:
        return {"jsonrpc": "2.0", "id": rid, "result": handle(msg["method"], params, data)}
    except RpcError as exc:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": exc.code, "message": str(exc)}}
    except Exception:  # never crash on input; never echo internals
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": "Internal error"}}


def serve(repo: Repo, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    data = Dataset(repo)
    while True:
        line = stdin.readline(MAX_LINE + 1)
        if not line:
            return 0
        if len(line) > MAX_LINE:
            while line and not line.endswith(b"\n"):  # drain the rest of the oversized line
                line = stdin.readline(MAX_LINE + 1)
            reply: dict | None = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "line too long (max 65536 bytes)"}}
        elif not line.strip():
            continue
        else:
            reply = respond(line, data)
        if reply is not None:
            try:
                body = json.dumps(reply).encode("ascii")  # ASCII JSON: lone surrogates are escaped, never raise
            except (UnicodeEncodeError, ValueError):
                body = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": "Internal error"}}).encode()
            stdout.write(body + b"\n")
            stdout.flush()
