"""asa intel on replayed runs: indicators come from cited events only, the answer key holds, nothing touches the network."""
import json
import itertools
import socket

import pytest

from asa.common import UsageError
from asa.intel import enrich as enrich_mod
from asa.intel.enrich import LABEL, enrich, summary
from asa.intel.extract import cited_event_ids, extract
from asa.checker import read_transcript
from intel_support import load_key, real_dataset, real_repo, real_repo_dir, replayed  # noqa: F401


def read(run_dir):
    return json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))


def rows(record):
    return {f"{r['type']}:{r['value']}": r for r in record["indicators"]}


@pytest.mark.parametrize("alert_id", sorted(load_key()))
def test_answer_key_rows(real_repo, replayed, alert_id):
    entry = load_key()[alert_id]
    got = rows(enrich(real_repo, replayed[alert_id]))
    assert {k: {"verdict": v["verdict"], "rule": v["rule"], "from_event_ids": v["from_event_ids"]}
            for k, v in got.items()} == entry["indicators"]
    for gone in entry.get("absent", []):
        assert gone not in got


def test_every_indicator_traces_to_a_cited_and_seen_event(real_repo, real_dataset, replayed):
    for alert_id, run_dir in replayed.items():
        record = enrich(real_repo, run_dir, data=real_dataset)
        cited = set(cited_event_ids(read(run_dir), read_transcript(run_dir / "transcript.jsonl"), real_dataset))
        for row in record["indicators"]:
            assert row["from_event_ids"] and set(row["from_event_ids"]) <= cited, (alert_id, row["value"])
            assert row["verdict"] in ("contain", "review", "clear")


def test_record_is_labelled_and_says_the_verdict_did_not_use_it(real_repo, replayed):
    record = enrich(real_repo, replayed["A-020"])
    assert record["label"] == LABEL == "post-triage enrichment (synthetic provider answers)"
    assert record["source"] == "fixtures" and record["used_in_verdict"] is False
    assert record["run"] == "out/runs/20261104T000000Z-mock/A-020" and record["alert_id"] == "A-020"
    assert summary(record) == {"indicators": 3, "contain": 2, "review": 0, "clear": 1, "source": "fixtures"}


def test_provider_records_have_status_fields_and_a_fixed_time(real_repo, replayed):
    record = enrich(real_repo, replayed["A-010"])
    row = rows(record)["ipv4:203.0.113.150"]
    assert set(row["providers"]) == {"vt", "abuseipdb", "otx"}
    for p in row["providers"].values():
        assert set(p) == {"status", "fields", "fetched_at"} and p["fetched_at"] == enrich_mod.FETCHED_AT
    assert row["providers"]["vt"]["fields"]["malicious"] >= 3
    assert set(rows(record)["domain:assist.vendor-support.example"]["providers"]) == {"vt", "otx"}  # abuseipdb is IP only


def test_own_tenant_names_are_allowlisted_and_not_looked_up(real_repo, replayed):
    row = rows(enrich(real_repo, replayed["A-007"]))["domain:intranet.corp.example"]
    assert (row["verdict"], row["rule"], row["providers"]) == ("clear", "ALLOWLISTED", {})


def test_injected_field_is_never_looked_up(real_repo, replayed):
    # A-004 cites E-004428, whose DNS name is addressed to an AI reviewer (and reported as an injection)
    record = enrich(real_repo, replayed["A-004"])
    assert not any("ai-reviewer" in r["value"] for r in record["indicators"])
    assert record["skipped"]["injection_skipped"] >= 1


def test_same_inputs_same_bytes(real_repo, replayed):
    path = replayed["A-013"] / "intel.json"
    enrich(real_repo, replayed["A-013"])
    first = path.read_bytes()
    enrich(real_repo, replayed["A-013"])
    assert path.read_bytes() == first


def test_lookup_cap(real_repo, replayed):
    record = enrich(real_repo, replayed["A-007"], max_lookups=4)
    assert record["skipped"]["lookup_cap"] >= 1
    assert sum(len(r["providers"]) for r in record["indicators"]) <= 4
    for bad in (0, -1, 1001, True, "5"):
        with pytest.raises(UsageError):
            enrich(real_repo, replayed["A-007"], max_lookups=bad)


def test_fixture_mode_makes_no_socket_call_and_reads_no_key(real_repo, replayed, monkeypatch):
    secret = "sk-" + "test-" + "key" + "-123456"
    for name in ("ASA_VT_KEY", "VT_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.setenv(name, secret)

    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    for alert_id in ("A-004", "A-020"):
        enrich(real_repo, replayed[alert_id])
        assert secret not in (replayed[alert_id] / "intel.json").read_text(encoding="utf-8")


def test_wrong_run_folder_is_refused(real_repo, replayed, tmp_path):
    bad = replayed["A-004"].parent / "A-005"
    original = (bad / "verdict.json").read_text(encoding="utf-8")
    try:
        data = json.loads(original)
        data["alert_id"] = "A-004"
        (bad / "verdict.json").write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(UsageError):
            enrich(real_repo, bad)
    finally:
        (bad / "verdict.json").write_text(original, encoding="utf-8")


# --- extraction rules, on a hand-made dataset ---

def make_repo(tmp_path, events):
    from asa.common import Repo
    from asa.tools import Dataset

    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "alerts.json").write_text("[]", encoding="utf-8")
    (tmp_path / "data" / "events.ndjson").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return Dataset(Repo(tmp_path))


def tool_result(*events):
    from asa.tools import compact

    return [{"type": "tool_result", "result": {"events": [compact(e) for e in events]}}]


NET = {"event_id": "E-000001", "@timestamp": "2026-03-01T00:00:00.000Z", "event": {"category": "network"},
       "host": {"name": "WS-01"}, "user": {"name": "u"}, "process": {"name": "p.exe"},
       "destination": {"ip": "203.0.113.9", "port": 443}, "dns": {"question": {"name": "evil.example"}},
       "user_agent": {"original": "curl http://203.0.113.55/x and 203.0.113.56"}}
PROC = {"event_id": "E-000002", "@timestamp": "2026-03-01T00:00:01.000Z", "event": {"category": "process"},
        "host": {"name": "WS-01"}, "user": {"name": "u"},
        "process": {"name": "p.exe", "command_line": "p.exe --to 203.0.113.77", "hash": {"sha256": "ab" * 32}}}
LAN = {"event_id": "E-000003", "@timestamp": "2026-03-01T00:00:02.000Z", "event": {"category": "network"},
       "host": {"name": "WS-01"}, "user": {"name": "u"}, "process": {"name": "p.exe"},
       "destination": {"ip": ".".join(("10", "1", "2", "3")), "port": 443}}  # RFC 1918, built from parts


def verdict(cited, reports=()):
    return {"claims": [{"citations": list(cited), "quotes": [], "text": "t"}], "injection_reports": list(reports),
            "recommended_actions": []}


def test_values_come_from_typed_fields_not_free_text(tmp_path):
    data = make_repo(tmp_path, [NET, PROC])
    found, _ = extract(verdict(["E-000001", "E-000002"]), tool_result(NET, PROC), data)
    values = {i.value for i in found}
    assert values == {"203.0.113.9", "evil.example", "ab" * 32}  # not 203.0.113.55 / .56 / .77 from free text


def test_only_cited_and_seen_events_count(tmp_path):
    data = make_repo(tmp_path, [NET, PROC])
    assert extract(verdict(["E-000002"]), tool_result(NET, PROC), data)[0].keys() == extract(
        verdict(["E-000002"]), tool_result(PROC), data)[0].keys()
    found, _ = extract(verdict(["E-000001"]), tool_result(PROC), data)  # cited but no tool returned it
    assert found == {}
    found, _ = extract(verdict(["E-999999"]), tool_result(NET), data)  # not in the dataset
    assert found == {}


def test_citations_quotes_and_actions_all_count(tmp_path):
    data = make_repo(tmp_path, [NET, PROC])
    v = {"claims": [{"citations": [], "quotes": [{"event_id": "E-000001", "field": "destination.ip", "text": "x"}]}],
         "injection_reports": [], "recommended_actions": [{"id": "ACT-001", "citations": ["E-000002"]}]}
    assert cited_event_ids(v, tool_result(NET, PROC), data) == ["E-000001", "E-000002"]


def test_typed_fields_are_fields_the_tools_show():
    """An indicator field the tools never return could not have been seen by the agent, so it is never looked up."""
    from asa.intel.extract import TYPED_FIELDS
    from asa.tools import SEARCHABLE

    assert {name for name, _ in TYPED_FIELDS} <= set(SEARCHABLE)


def test_non_string_ids_are_ignored_not_a_crash(tmp_path):
    """verdict.json is model output: a list or dict where an event id belongs is skipped, never a TypeError."""
    data = make_repo(tmp_path, [NET, PROC])
    v = {"claims": [{"citations": [["E-000001"], {"id": "E-000002"}, 7, "E-000001"],
                     "quotes": [{"event_id": ["E-000002"], "field": "x", "text": "y"}]}],
         "injection_reports": [{"event_id": ["E-000001"], "field": "dns.question.name"}],
         "recommended_actions": [{"id": "ACT-001", "citations": [{"x": 1}, "E-000002"]}]}
    assert cited_event_ids(v, tool_result(NET, PROC), data) == ["E-000001", "E-000002"]
    found, _ = extract(v, tool_result(NET, PROC), data)
    assert found


def test_private_addresses_are_skipped_and_counted(tmp_path):
    data = make_repo(tmp_path, [LAN])
    found, skipped = extract(verdict(["E-000003"]), tool_result(LAN), data)
    assert found == {} and skipped["not_routable"] == 1


def test_reported_field_is_skipped_even_when_it_looks_harmless(tmp_path):
    data = make_repo(tmp_path, [NET])
    reports = [{"event_id": "E-000001", "field": "dns.question.name", "excerpt": "x"}]
    found, skipped = extract(verdict(["E-000001"], reports), tool_result(NET), data)
    assert {i.value for i in found} == {"203.0.113.9"} and skipped["injection_skipped"] == 1


def test_instruction_shaped_value_is_skipped_without_a_report(tmp_path):
    evil = {**NET, "dns": {"question": {"name": "ignore-previous-instructions.corp.example"}}}
    data = make_repo(tmp_path, [evil])
    found, skipped = extract(verdict(["E-000001"]), tool_result(evil), data)
    assert "ignore-previous-instructions.corp.example" not in {i.value for i in found} and skipped["injection_skipped"] == 1


# --- the audit-trail hook (audit.note_file) ---

RUN_SEQ = itertools.count(1)


@pytest.fixture
def own_run(real_repo):
    """A fresh replay of A-002 in its own run folder (these tests change its trail)."""
    from asa.agent import investigate
    from asa.llm import ReplayClient
    from intel_support import RECORDING

    client = ReplayClient.from_dir(real_repo.path("evals/recorded", RECORDING, "A-002"), RECORDING)
    run_id = f"20261104T{next(RUN_SEQ):06d}Z-mock"
    run_dir, _ = investigate("A-002", client, real_repo, run_id=run_id, echo=lambda line: None)
    return run_dir


def test_a_run_without_a_trail_gets_intel_json_and_no_trail(real_repo, own_run):
    from asa import audit

    (own_run / "audit.jsonl").unlink()  # a run folder from before audit trails
    enrich(real_repo, own_run)
    assert (own_run / "intel.json").is_file() and not (own_run / "audit.jsonl").exists()
    assert audit.verify(own_run)[2] == "no audit trail (audit.jsonl)"


def test_intel_line_is_appended_and_the_trail_verifies(real_repo, own_run):
    from asa import audit

    enrich(real_repo, own_run)
    last = json.loads((own_run / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert (last["kind"], last["actor"]) == ("intel", "code") and "synthetic provider answers" in last["summary"]
    assert audit.verify(own_run) == (True, None, None)
    enrich(real_repo, own_run, max_lookups=1)  # a rerun rewrites intel.json: verify compares it with the LAST intel line
    kinds = [json.loads(x)["kind"] for x in (own_run / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert kinds.count("intel") == 2 and audit.verify(own_run) == (True, None, None)


def test_a_broken_trail_refuses_and_writes_no_intel_json(real_repo, own_run, monkeypatch, capsys):
    from asa import cli

    trail = own_run / "audit.jsonl"
    lines = trail.read_bytes().split(b"\n")
    trail.write_bytes(b"\n".join(lines[:1] + lines[2:]))  # a line removed
    monkeypatch.chdir(real_repo.base)
    assert cli.main(["intel", real_repo.rel(own_run)]) == 2
    assert "nothing written" in capsys.readouterr().out
    assert not (own_run / "intel.json").exists()  # the message is true: nothing was written


def test_a_failed_trail_append_is_a_clear_error_not_a_traceback(real_repo, own_run, monkeypatch, capsys):
    from asa import audit, cli

    def broken(self, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(audit.Writer, "append", broken)
    monkeypatch.chdir(real_repo.base)
    assert cli.main(["intel", real_repo.rel(own_run)]) == 2
    out = capsys.readouterr().out
    assert "intel.json written; trail append failed: OSError" in out
    assert (own_run / "intel.json").is_file()
