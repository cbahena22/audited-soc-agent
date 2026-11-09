"""The README's buyer's checklist is generated from checklist/checklist.json and must match it, row by row."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("render_checklist", ROOT / "tools" / "render_checklist.py")
render_checklist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render_checklist)

ROWS = json.loads((ROOT / "checklist" / "checklist.json").read_text(encoding="utf-8"))
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_table_is_what_the_renderer_makes():
    assert render_checklist.current_table(README) == render_checklist.render(ROWS)
    assert render_checklist.rewritten(README, ROWS) == README


def test_check_mode_passes_on_this_checkout(capsys):
    assert render_checklist.main(["--check"]) == 0
    assert "matches" in capsys.readouterr().out


def test_check_mode_fails_on_a_stale_table(tmp_path, monkeypatch, capsys):
    (tmp_path / "checklist").mkdir()
    (tmp_path / "checklist" / "checklist.json").write_text(json.dumps(ROWS), encoding="utf-8")
    stale = README.replace("**Can it change anything in my environment?**", "**Can it change anything?**")
    assert stale != README
    (tmp_path / "README.md").write_text(stale, encoding="utf-8")
    monkeypatch.setattr(render_checklist, "ROOT", tmp_path)
    assert render_checklist.main(["--check"]) == 1
    assert "out of date" in capsys.readouterr().err
    assert render_checklist.main([]) == 0  # rewrite
    assert render_checklist.main(["--check"]) == 0


def test_every_row_is_in_the_readme_and_none_is_pending():
    assert len(ROWS) >= 10
    for row in ROWS:
        assert not row.get("pending"), row["id"]
        assert f"| {row['id']} |" in README
        for key in ("question", "answer", "console_view", "code", "tests", "limits"):
            assert row[key], (row["id"], key)


@pytest.mark.parametrize("view,expected", [("case:A-007#injection", "console: case A-007 › injection"), ("queue", "console: queue"), ("about#limits", "console: about › limits")])
def test_view_text(view, expected):
    assert render_checklist.view_text(view) == expected


def test_a_bad_view_is_refused():
    with pytest.raises(ValueError):
        render_checklist.view_text("somewhere else")


def test_links_point_at_real_files():
    for row in ROWS:
        for ref in row["code"] + row["tests"]:
            assert (ROOT / ref.partition("::")[0]).is_file(), ref
