import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_rootdir_is_the_subfolder(request):
    assert Path(request.config.rootpath).resolve() == ROOT
    assert (ROOT / "pyproject.toml").is_file()


def test_colorama_win32_marker_in_dev_lock():
    text = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
    assert re.search(r"^colorama==\S+ ; sys_platform == 'win32'", text, re.M)


def test_every_lock_entry_has_hashes():
    for name in ("requirements.lock", "requirements-dev.lock"):
        lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
        entries = [i for i, line in enumerate(lines) if re.match(r"^[A-Za-z0-9_.-]+==", line)]
        assert entries, name
        for i in entries:
            assert lines[i].rstrip().endswith("\\") and "--hash=sha256:" in lines[i + 1], (name, lines[i])
