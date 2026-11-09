"""The five read-only tools the agent (and the MCP server) may call. They read `data/` only and check every argument in code."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .common import ALERT_ID, ENTITY_ID, HOST, Repo, UsageError, check_id as _check_id

DEFAULT_LIMIT = 20
MAX_LIMIT = 50
MAX_WINDOW = timedelta(hours=24)
MAX_MINUTES = 60
MAX_VALUE_CHARS = 200
CUT = " [cut]"
KINDS = ("process", "network", "logon", "file")

# Compact event view: a short fixed field set per kind keeps tool results small.
COMMON_FIELDS = ("user.name", "rule.name", "threat.technique.id", "event.severity", "event.outcome")
KIND_FIELDS = {
    "process": ("process.name", "process.entity_id", "process.command_line", "process.hash.sha256",
                "process.parent.name", "process.parent.entity_id"),
    "network": ("process.name", "destination.ip", "destination.port", "dns.question.name", "user_agent.original"),
    "logon": ("logon.type", "source.ip"),
    "file": ("process.name", "process.entity_id", "file.path", "file.name"),
}
SEARCHABLE = tuple(sorted({f for fields in KIND_FIELDS.values() for f in fields} | set(COMMON_FIELDS)))


class ToolError(UsageError):
    """A tool argument was refused; the agent gets it back as an error result."""


def check_id(pattern, value: Any, what: str) -> str:
    return _check_id(pattern, value, what, ToolError)


# parse_time, iso and get_field are adapted from earlier code by the author, with new docstrings.
def parse_time(value: str | None) -> datetime | None:
    """ISO 8601 text to an aware UTC datetime ("Z" accepted). A value without a zone is read as UTC."""
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    """UTC datetime to ISO 8601 with milliseconds and a "Z" suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if dt else None


def get_field(doc: Any, path: str) -> Any:
    """Read a dotted field ("process.parent.name") from a doc with nested objects, flat dotted keys, or both."""
    if not isinstance(doc, dict):
        return None
    if path in doc:
        return doc[path]
    parts = path.split(".")
    # Try every split point: a flat prefix key plus a nested remainder.
    for i in range(len(parts) - 1, 0, -1):
        head = ".".join(parts[:i])
        if head in doc:
            found = get_field(doc[head], ".".join(parts[i:]))
            if found is not None:
                return found
    return None


def _time_arg(value: Any, what: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ToolError(f"bad {what}: expected an ISO 8601 time such as 2026-03-02T09:00:00Z")
    try:
        return parse_time(value)
    except (ValueError, OverflowError):
        raise ToolError(f"bad {what}: expected an ISO 8601 time such as 2026-03-02T09:00:00Z") from None


def _limit_arg(value: Any) -> int:
    if value is None:
        return DEFAULT_LIMIT
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ToolError("bad limit: expected a whole number from 1")
    return min(value, MAX_LIMIT)


def _window(start: Any, end: Any) -> tuple[datetime, datetime]:
    t0, t1 = _time_arg(start, "start"), _time_arg(end, "end")
    if t1 < t0:
        raise ToolError("bad window: end is before start")
    if t1 - t0 > MAX_WINDOW:
        raise ToolError("bad window: at most 24 hours")
    return t0, t1


def _short(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return value[:MAX_VALUE_CHARS] + CUT
    return value


def compact(event: dict) -> dict:
    """The compact event view returned by every tool: id, time, host, kind and the fields of that kind."""
    kind = get_field(event, "event.category")
    view = {"event_id": event.get("event_id"), "@timestamp": event.get("@timestamp"),
            "host": get_field(event, "host.name"), "kind": kind}
    for name in COMMON_FIELDS + KIND_FIELDS.get(kind, ()):
        value = get_field(event, name)
        if value is not None:
            view[name] = _short(value)
    signals = event.get("signal")
    if isinstance(signals, dict):
        for key in sorted(signals):
            view[f"signal.{key}"] = _short(signals[key])
    return view


class Dataset:
    """Alerts and events loaded once from `data/` (opened read-only). The answer key lives outside `data/`."""

    def __init__(self, repo: Repo):
        self.repo = repo
        with repo.path("data", "alerts.json").open("r", encoding="utf-8") as f:
            self.alerts = {a["alert_id"]: a for a in json.load(f)}
        self.events: list[dict] = []
        with repo.path("data", "events.ndjson").open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    event["_t"] = parse_time(event["@timestamp"])
                    self.events.append(event)
        self.events.sort(key=lambda e: (e["_t"], e["event_id"]))
        self.by_id = {e["event_id"]: e for e in self.events}

    def _host_events(self, host: str, t0: datetime, t1: datetime, kind: str | None = None):
        for e in self.events:
            if t0 <= e["_t"] <= t1 and get_field(e, "host.name") == host and (kind is None or get_field(e, "event.category") == kind):
                yield e

    @staticmethod
    def _page(events, limit: int) -> dict:
        found = list(events)
        return {"events": [compact(e) for e in found[:limit]], "count": min(len(found), limit), "truncated": len(found) > limit}

    def get_alert(self, alert_id: Any) -> dict:
        check_id(ALERT_ID, alert_id, "alert_id")
        alert = self.alerts.get(alert_id)
        if alert is None:
            raise ToolError(f"no such alert: {alert_id}")
        return {"alert": alert}

    def search_events(self, host: Any, start: Any, end: Any, field: Any = None, value: Any = None, limit: Any = None) -> dict:
        check_id(HOST, host, "host")
        t0, t1 = _window(start, end)
        n = _limit_arg(limit)
        if (field is None) != (value is None):
            raise ToolError("bad filter: give both field and value, or neither")
        if field is not None:
            if field not in SEARCHABLE:
                raise ToolError("bad field: use one of " + ", ".join(SEARCHABLE))
            if not isinstance(value, (str, int)) or isinstance(value, bool) or len(str(value)) > MAX_VALUE_CHARS:
                raise ToolError("bad value: a string or number, at most 200 characters")
            needle = str(value).casefold()
            events = (e for e in self._host_events(host, t0, t1)
                      if get_field(e, field) is not None and needle in str(get_field(e, field)).casefold())
        else:
            events = self._host_events(host, t0, t1)
        return self._page(events, n)

    def process_tree(self, host: Any, process_entity_id: Any) -> dict:
        check_id(HOST, host, "host")
        check_id(ENTITY_ID, process_entity_id, "process_entity_id")
        procs = [e for e in self.events if get_field(e, "host.name") == host and get_field(e, "event.category") == "process"]
        node = next((e for e in procs if get_field(e, "process.entity_id") == process_entity_id), None)
        if node is None:
            raise ToolError(f"no process {process_entity_id} on {host}")
        parent_id = get_field(node, "process.parent.entity_id")
        parent = next((e for e in procs if parent_id and get_field(e, "process.entity_id") == parent_id), None)
        children = [e for e in procs if get_field(e, "process.parent.entity_id") == process_entity_id]
        return {"process": compact(node), "parent": compact(parent) if parent else None,
                "children": [compact(e) for e in children[:MAX_LIMIT]], "truncated": len(children) > MAX_LIMIT}

    def network_connections(self, host: Any, start: Any, end: Any, limit: Any = None) -> dict:
        check_id(HOST, host, "host")
        t0, t1 = _window(start, end)
        return self._page(self._host_events(host, t0, t1, kind="network"), _limit_arg(limit))

    def host_timeline(self, host: Any, around: Any, minutes: Any = None) -> dict:
        check_id(HOST, host, "host")
        center = _time_arg(around, "around")
        if minutes is None:
            minutes = 15
        if isinstance(minutes, bool) or not isinstance(minutes, int) or minutes < 1:
            raise ToolError("bad minutes: expected a whole number from 1")
        span = timedelta(minutes=min(minutes, MAX_MINUTES))
        try:
            t0, t1 = center - span, center + span
        except OverflowError:
            raise ToolError("bad around: out of range") from None
        return self._page(self._host_events(host, t0, t1), MAX_LIMIT)

    def call(self, name: str, args: Any) -> dict:
        """Run one tool by name with a dict of arguments; unknown names and extra arguments are refused."""
        if name not in TOOL_ARGS:
            raise ToolError(f"unknown tool: {name}")
        if not isinstance(args, dict):
            raise ToolError("arguments must be an object")
        extra = set(args) - set(TOOL_ARGS[name])
        if extra:
            raise ToolError("unknown argument: " + ", ".join(sorted(map(str, extra))))
        return getattr(self, name)(**{k: args.get(k) for k in TOOL_ARGS[name]})


TOOL_ARGS = {
    "get_alert": ("alert_id",),
    "search_events": ("host", "start", "end", "field", "value", "limit"),
    "process_tree": ("host", "process_entity_id"),
    "network_connections": ("host", "start", "end", "limit"),
    "host_timeline": ("host", "around", "minutes"),
}


def _nullable(kind: str, description: str) -> dict:
    return {"anyOf": [{"type": kind}, {"type": "null"}], "description": description}


_HOST = {"type": "string", "description": "Host name, WS-01..WS-12 or SRV-01..SRV-03."}
_TIME = "ISO 8601 UTC time, e.g. 2026-03-02T09:00:00Z."
_LIMIT = _nullable("integer", "Max events, default 20, capped at 50. Null for the default.")

# JSON Schemas for the five tools. Strict-friendly: every property required, optional ones nullable,
# no additionalProperties, no numeric or length bounds (caps and id patterns are checked in code above).
TOOL_SCHEMAS = {
    "get_alert": {
        "description": "The alert card for one alert id (A-001..A-030).",
        "properties": {"alert_id": {"type": "string", "description": "Alert id, e.g. A-007."}},
    },
    "search_events": {
        "description": "Events on one host in a time window (at most 24 h), optionally where a field contains a value "
                       "(case-insensitive). Returns the compact event view.",
        "properties": {"host": _HOST, "start": {"type": "string", "description": _TIME},
                       "end": {"type": "string", "description": _TIME},
                       "field": _nullable("string", "Dotted field name to filter on, e.g. process.name. Null for no filter."),
                       "value": _nullable("string", "Text the field must contain. Null when field is null."),
                       "limit": _LIMIT},
    },
    "process_tree": {
        "description": "One process with its parent and direct children, by process entity id (P- plus 12 hex).",
        "properties": {"host": _HOST, "process_entity_id": {"type": "string", "description": "e.g. P-0a0000000103."}},
    },
    "network_connections": {
        "description": "Network events (destination, DNS name, user agent) on one host in a time window (at most 24 h).",
        "properties": {"host": _HOST, "start": {"type": "string", "description": _TIME},
                       "end": {"type": "string", "description": _TIME}, "limit": _LIMIT},
    },
    "host_timeline": {
        "description": "All events on one host within N minutes before and after a time (N capped at 60, up to 50 events).",
        "properties": {"host": _HOST, "around": {"type": "string", "description": _TIME},
                       "minutes": _nullable("integer", "Minutes each side, default 15, capped at 60. Null for the default.")},
    },
}


def input_schema(name: str) -> dict:
    spec = TOOL_SCHEMAS[name]
    return {"type": "object", "properties": spec["properties"], "required": list(TOOL_ARGS[name]),
            "additionalProperties": False}
