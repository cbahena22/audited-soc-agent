import ast
import json
from pathlib import Path

import pytest

from asa import cli
from asa.actions import STATUS
from test_checker import RUN, make_run

SRC = Path(__file__).resolve().parents[1] / "src" / "asa"


@pytest.fixture
def run_dir(repo, repo_dir, monkeypatch):
    path = make_run(repo)
    monkeypatch.chdir(repo_dir)
    return path


def lines(run_dir):
    path = run_dir / "approvals.jsonl"
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def test_status_text_is_exact():
    assert STATUS == "approved (dry run, not sent)"


def test_approve_appends_one_dry_run_line(run_dir, capsys):
    assert cli.main(["approve", "ACT-001", "--run", RUN, "--as", "Night Lead"]) == 0
    assert capsys.readouterr().out.strip() == "ACT-001 approved (dry run, not sent) by Night Lead"
    [line] = lines(run_dir)
    assert set(line) == {"id", "by", "at", "status"}
    assert (line["id"], line["by"], line["status"]) == ("ACT-001", "Night Lead", "approved (dry run, not sent)")


def test_approving_twice_is_a_no_op_with_a_message(run_dir, capsys):
    assert cli.main(["approve", "ACT-001", "--run", RUN, "--as", "Night Lead"]) == 0
    assert cli.main(["approve", "ACT-001", "--run", RUN, "--as", "Day Lead"]) == 0
    assert "already approved (dry run, not sent) by Night Lead; nothing changed" in capsys.readouterr().out
    assert len(lines(run_dir)) == 1


def test_actions_lists_citations_and_state(run_dir, capsys):
    cli.main(["approve", "ACT-002", "--run", RUN, "--as", "Day-Shift O'Lead Jr."])
    capsys.readouterr()
    assert cli.main(["actions", RUN]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("ACT-001 isolate_host WS-03: ") and out[0].endswith("[cites E-000103] - waiting for a person")
    assert out[1].endswith("- approved (dry run, not sent) by Day-Shift O'Lead Jr.")


@pytest.mark.parametrize("name", ["", "1abc", "N" * 42, "Night\nLead", "<b>Lead</b>", "Lead; rm", "Night_Lead", "Nüt"])
def test_bad_approver_name_refused(run_dir, capsys, name):
    assert cli.main(["approve", "ACT-001", "--run", RUN, "--as", name]) == 2
    assert capsys.readouterr().out.startswith("asa: bad --as") and lines(run_dir) == []


@pytest.mark.parametrize("action_id", ["ACT-1", "act-001", "../ACT-001", "ACT-009"])
def test_bad_or_unknown_action_id_refused(run_dir, capsys, action_id):
    assert cli.main(["approve", action_id, "--run", RUN, "--as", "Night Lead"]) == 2
    assert lines(run_dir) == []


@pytest.mark.parametrize("run", ["../..", "data", "evals/recorded", "out/runs/20261027T000000Z-mock/A-007/..",
                                 "out/runs/20261027T000000Z-mock/../../../data/A-007"])
def test_run_folder_must_stay_inside_out(run_dir, repo_dir, capsys, run):
    assert cli.main(["approve", "ACT-001", "--run", run, "--as", "Night Lead"]) == 2
    assert [p for p in repo_dir.rglob("approvals.jsonl")] == []


def test_no_module_defines_a_send_or_execute_path():
    words = ("send", "execute", "exec", "dispatch", "perform", "carry_out", "invoke", "trigger", "run_action", "apply_action")
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assert not any(w in node.name.lower() for w in words), (path.name, node.name)
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                assert name not in ("system", "popen", "Popen", "startfile", "exec", "eval"), (path.name, name)
    # actions.py writes only approvals.jsonl through append_jsonl; it never opens a file for writing itself.
    source = (SRC / "actions.py").read_text(encoding="utf-8")
    assert "write_text" not in source and '"w"' not in source and "'w'" not in source
