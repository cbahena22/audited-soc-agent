"""The buyer's checklist: every row points at code and tests that exist (AST lookup, no test module is imported),
and the numbers it quotes match the recorded results."""
import ast
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROWS = json.loads((ROOT / "checklist" / "checklist.json").read_text(encoding="utf-8"))
FIELDS = {"id", "question", "answer", "console_view", "code", "tests", "limits"}
# the console grammar (console/pages.py VIEW_RX): queue | checklist | about | case:A-NNN | trust:A-NNN | audit:A-NNN, + #anchor
VIEW = re.compile(r"^(?:(queue|checklist|about)|(case|trust|audit):A-\d{3})(#[a-z-]+)?$")
REF = re.compile(r"^((?:src/asa|tests)/[a-z_/]+\.py)::([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)$")


def defined(path: Path, symbol: str) -> bool:
    """True when `symbol` (name or Class.method) is defined at the top level of the module at `path`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    head, _, member = symbol.partition(".")
    for node in tree.body:
        names = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
        if head not in names:
            continue
        if not member:
            return True
        if isinstance(node, ast.ClassDef):
            return any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == member for n in node.body)
    return False


def resolve(ref: str) -> bool:
    match = REF.fullmatch(ref)
    if not match:
        return False
    path = (ROOT / match.group(1)).resolve()
    return ROOT in path.parents and path.is_file() and defined(path, match.group(2))


def live_rows():
    return [r for r in ROWS if not r.get("pending")]


def test_row_shape_and_ids():
    assert 10 <= len(ROWS) <= 12
    assert [r["id"] for r in ROWS] == [f"Q{i:02d}" for i in range(1, len(ROWS) + 1)]
    for row in ROWS:
        assert FIELDS <= set(row) <= FIELDS | {"pending"}, row["id"]
        assert row["question"].endswith("?") and row["limits"], row["id"]
        assert len(re.findall(r"[.!?](?:\s|$)", row["answer"].strip())) <= 2, row["id"]  # two sentences at most
        assert row.get("pending", False) in (True, False)


@pytest.mark.parametrize("row", live_rows(), ids=lambda r: r["id"])
def test_every_named_code_and_test_exists(row):
    assert row["code"] and row["tests"] and VIEW.fullmatch(row["console_view"]), row["id"]
    for ref in row["code"]:
        assert ref.startswith("src/asa/") and resolve(ref), ref
    for ref in row["tests"]:
        assert ref.startswith("tests/test_") and resolve(ref) and ref.split("::")[1].startswith("test_"), ref


def test_the_lookup_catches_drift():
    assert resolve("src/asa/audit.py::verify") and resolve("src/asa/audit.py::Trail.append")
    assert resolve("tests/test_audit.py::test_chain_tamper_fails_at_the_right_seq")
    for bad in ("src/asa/audit.py::no_such_function", "src/asa/audit.py::Trail.no_such_method", "src/asa/nothing.py::verify",
                "tests/test_audit.py::test_does_not_exist", "src/asa/../../outside.py::x", "src/asa/audit.py",
                "src/asa/audit.py::verify.inner"):
        assert not resolve(bad), bad


def test_no_row_is_pending():
    assert [r["id"] for r in ROWS if r.get("pending")] == []
    assert all(FIELDS == set(r) for r in ROWS)


def test_quoted_numbers_match_the_results():
    results = json.loads((ROOT / "evals" / "results.json").read_text(encoding="utf-8"))
    t, i = results["triage"], results["injection"]
    by_id = {r["id"]: r["answer"] for r in ROWS}
    assert f"{t['accuracy']['correct']} of {t['n']} verdicts" in by_id["Q08"]
    assert f"{t['baseline']['correct']} of {t['n']} for a rule" in by_id["Q08"]
    assert f"Only {t['n_malicious']} of the {t['n']} alerts is malicious" in by_id["Q08"]
    assert f"{t['needs_human']['k']} needs_human answers where the key expects {sum(t['confusion']['needs_human'].values())}" in by_id["Q09"]
    assert f"{t['unsupported_claims']['k']} unsupported claims in {t['unsupported_claims']['n']}" in by_id["Q03"]
    assert f"${t['cost_usd']['mean']:.3f} on average and ${t['cost_usd']['max']:.3f} at most" in by_id["Q07"]
    assert f"{i['n']} planted texts" in by_id["Q02"] and f"reported all {i['reported']}" in by_id["Q02"]


def test_plain_words_only():
    text = (ROOT / "checklist" / "checklist.json").read_text(encoding="utf-8")
    # words a private evaluation framework would use; built from parts so this file does not hold them itself
    words = ["q" + "c", "rub" + "ric", "gold.?" + "label", "adver" + "sarial", "jud" + "g"]
    assert not re.search("|".join(words), text, re.I)
    assert "reasoned past" not in text
