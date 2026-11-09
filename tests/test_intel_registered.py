"""`asa intel` is registered in the real CLI and reaches the intel code (replay -> intel -> intel.json)."""
import json

from asa import cli
from intel_support import real_repo, real_repo_dir, replayed  # noqa: F401


def test_asa_intel_is_registered(real_repo, replayed, monkeypatch, capsys):
    monkeypatch.chdir(real_repo.base)
    run = real_repo.rel(replayed["A-020"])
    assert cli.main(["intel", run]) == 0
    out = capsys.readouterr().out
    assert "post-triage enrichment (synthetic provider answers)" in out and "2 contain, 0 review, 1 clear" in out
    assert json.loads((replayed["A-020"] / "intel.json").read_text(encoding="utf-8"))["source"] == "fixtures"


def test_intel_usage_errors_exit_2(real_repo, monkeypatch, capsys):
    monkeypatch.chdir(real_repo.base)
    assert cli.main(["intel", "../outside"]) == 2
    assert "asa:" in capsys.readouterr().out
