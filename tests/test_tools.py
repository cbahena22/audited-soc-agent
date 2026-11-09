import json

import pytest

from asa.common import Repo, UsageError
from asa.tools import KIND_FIELDS, MAX_VALUE_CHARS, TOOL_ARGS, Dataset, ToolError

DAY = {"start": "2026-03-02T00:00:00Z", "end": "2026-03-02T23:59:59Z"}


def add_events(repo_dir, events):
    with (repo_dir / "data" / "events.ndjson").open("a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def filler(n, host="WS-03"):
    return [{"event_id": f"E-9{i:05d}", "@timestamp": f"2026-03-02T12:{i // 60:02d}:{i % 60:02d}.000Z",
             "event": {"category": "logon", "outcome": "success"}, "host": {"name": host},
             "user": {"name": "user03"}, "logon": {"type": "unlock"}} for i in range(n)]


@pytest.mark.parametrize("bad", ["../", "A-7", "A-0071", "a-007", "../evals/answer_key.json", "", None, 7])
def test_bad_alert_ids_refused(dataset, bad):
    with pytest.raises(ToolError):
        dataset.call("get_alert", {"alert_id": bad})


@pytest.mark.parametrize("bad", ["WS-01;", "ws-01", "WS-1", "../data", "DC-01", "WS-01\n", None])
def test_bad_hosts_refused(dataset, bad):
    with pytest.raises(ToolError):
        dataset.call("search_events", {"host": bad, **DAY, "field": None, "value": None, "limit": None})


def test_bad_entity_id_refused(dataset):
    for bad in ["P-xyz", "P-0a0000000103/..", "E-000103"]:
        with pytest.raises(ToolError):
            dataset.call("process_tree", {"host": "WS-03", "process_entity_id": bad})


def test_unknown_tool_and_extra_argument_refused(dataset):
    with pytest.raises(ToolError):
        dataset.call("read_file", {"path": "evals/answer_key.json"})
    with pytest.raises(ToolError):
        dataset.call("get_alert", {"alert_id": "A-007", "path": "../evals/answer_key.json"})


def test_default_limit_20_and_cap_50(repo_dir):
    add_events(repo_dir, filler(80))
    ds = Dataset(Repo(repo_dir))
    base = {"host": "WS-03", **DAY, "field": None, "value": None}
    r = ds.call("search_events", {**base, "limit": None})
    assert r["count"] == 20 and r["truncated"] is True
    r = ds.call("search_events", {**base, "limit": 500})
    assert r["count"] == 50 and len(r["events"]) == 50 and r["truncated"] is True
    with pytest.raises(ToolError):
        ds.call("search_events", {**base, "limit": 0})
    r = ds.call("network_connections", {"host": "WS-03", **DAY, "limit": None})
    assert r["truncated"] is False and all(e["kind"] == "network" for e in r["events"])
    r = ds.call("host_timeline", {"host": "WS-03", "around": "2026-03-02T12:30:00Z", "minutes": 600})
    assert r["count"] == 50 and r["truncated"] is True  # minutes capped at 60, results at 50


def test_window_caps(dataset):
    with pytest.raises(ToolError, match="24 hours"):
        dataset.call("search_events", {"host": "WS-03", "start": "2026-03-01T00:00:00Z", "end": "2026-03-02T00:00:01Z",
                                       "field": None, "value": None, "limit": None})
    with pytest.raises(ToolError, match="before start"):
        dataset.call("network_connections", {"host": "WS-03", "start": DAY["end"], "end": DAY["start"], "limit": None})
    with pytest.raises(ToolError):
        dataset.call("host_timeline", {"host": "WS-03", "around": "yesterday", "minutes": 5})
    with pytest.raises(ToolError):
        dataset.call("host_timeline", {"host": "WS-03", "around": "2026-03-02T09:00:00Z", "minutes": 0})


@pytest.mark.parametrize("edge", ["0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "0001-01-01T00:30:00+01:00"])
def test_out_of_range_times_are_tool_errors(dataset, edge):
    with pytest.raises(ToolError):
        dataset.call("host_timeline", {"host": "WS-03", "around": edge, "minutes": 60})
    if edge.endswith("+01:00"):  # converting to UTC leaves the datetime range
        with pytest.raises(ToolError):
            dataset.call("search_events", {"host": "WS-03", "start": edge, "end": edge, "field": None, "value": None, "limit": None})


def test_timeline_minutes_capped_at_60(dataset):
    r = dataset.call("host_timeline", {"host": "WS-03", "around": "2026-03-02T10:02:31Z", "minutes": 1000})
    ids = {e["event_id"] for e in r["events"]}
    assert ids == {"E-000103", "E-000104", "E-000105"}  # the 08:58 events are 64 minutes before: outside the cap


def test_search_filter(dataset):
    r = dataset.call("search_events", {"host": "WS-03", **DAY, "field": "process.name", "value": "PowerShell", "limit": None})
    assert [e["event_id"] for e in r["events"]] == ["E-000103"]
    with pytest.raises(ToolError):
        dataset.call("search_events", {"host": "WS-03", **DAY, "field": "_t", "value": "x", "limit": None})
    with pytest.raises(ToolError):
        dataset.call("search_events", {"host": "WS-03", **DAY, "field": "process.name", "value": None, "limit": None})


def test_path_outside_data_refused(repo):
    for root, parts in [("data", ("..", "evals", "answer_key.json")), ("data", ("..", "..")), ("evals", ("answer_key.json",))]:
        with pytest.raises(UsageError):
            repo.path(root, *parts)
    with pytest.raises(UsageError):
        repo.path("data", "x", write=True)


def test_answer_key_unreachable(dataset, repo_dir):
    """No argument to any tool returns answer-key content: the expected-verdict text never shows up."""
    probes = ["../evals/answer_key.json", "evals/answer_key.json", "expected_verdict", "A-007", "WS-03", "P-0a0000000103"]
    seen = []
    for name, params in TOOL_ARGS.items():
        for probe in probes:
            args = {p: probe for p in params}
            try:
                seen.append(json.dumps(dataset.call(name, args)))
            except ToolError:
                pass
    assert seen  # some probes are valid ids and do return data
    assert not any("expected_verdict" in s or "planted_injection" in s for s in seen)


def test_compact_view_fields_per_kind(dataset):
    r = dataset.call("search_events", {"host": "WS-03", **DAY, "field": None, "value": None, "limit": None})
    for view in r["events"]:
        allowed = {"event_id", "@timestamp", "host", "kind", "user.name", "rule.name", "threat.technique.id",
                   "event.severity", "event.outcome", *KIND_FIELDS[view["kind"]]}
        assert {k for k in view if not k.startswith("signal.")} <= allowed
        assert "_t" not in view
    trigger = dataset.process_tree("WS-03", "P-0a0000000103")["process"]
    assert trigger["signal.rare_destination"] == "198.51.100.23"


def test_long_values_cut(repo_dir):
    add_events(repo_dir, [{"event_id": "E-990001", "@timestamp": "2026-03-02T15:00:00.000Z",
                           "event": {"category": "file"}, "host": {"name": "WS-03"},
                           "file": {"name": "x" * 1000, "path": "C:\\Temp\\long.txt"}}])
    ds = Dataset(Repo(repo_dir))
    view = ds.call("search_events", {"host": "WS-03", **DAY, "field": "file.path", "value": "long", "limit": None})["events"][0]
    assert view["file.name"].endswith("[cut]") and len(view["file.name"]) == MAX_VALUE_CHARS + len(" [cut]")


def test_process_tree_parent_and_children(dataset):
    r = dataset.call("process_tree", {"host": "WS-03", "process_entity_id": "P-0a0000000102"})
    assert r["process"]["event_id"] == "E-000102" and r["parent"] is None
    assert sorted(c["event_id"] for c in r["children"]) == ["E-000103", "E-000105"]
    with pytest.raises(ToolError):
        dataset.call("process_tree", {"host": "WS-05", "process_entity_id": "P-0a0000000102"})


def test_repo_requires_alerts_file(tmp_path):
    with pytest.raises(UsageError, match="alerts.json"):
        Repo(tmp_path)
