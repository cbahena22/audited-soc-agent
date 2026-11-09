"""A regular (non-editable) install must carry its package data (intel config, console assets) and run `asa demo` from the working folder."""
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run(cmd, cwd, timeout=900):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def test_non_editable_install_runs_the_demo_from_the_working_folder(tmp_path):
    env = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True).create(env)
    py = str(env / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python"))
    inst = _run([py, "-m", "pip", "install", "--quiet", "--require-hashes", "-r", "requirements.lock"], ROOT)
    if inst.returncode != 0:
        pytest.skip("cannot install the locked dependencies here (offline?): " + inst.stderr[-200:])
    # build from a copy: pip writes build/ and *.egg-info next to the sources, never into the checkout
    src = tmp_path / "src_copy"
    src.mkdir()
    shutil.copytree(ROOT / "src", src / "src", ignore=shutil.ignore_patterns("*.egg-info", "__pycache__"))
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy(ROOT / name, src / name)
    build = _run([py, "-m", "pip", "install", "--quiet", "--no-deps", str(src)], tmp_path)
    if build.returncode != 0 and "setuptools" in build.stderr:
        pytest.skip("cannot fetch the build backend here (offline?): " + build.stderr[-200:])
    assert build.returncode == 0, build.stderr[-500:]
    where = _run([py, "-c", "import asa; print(asa.__file__)"], tmp_path)
    assert "site-packages" in where.stdout, where.stdout
    work = tmp_path / "work"  # the folder a user runs from: data and recording only, no source tree
    work.mkdir()
    shutil.copytree(ROOT / "data", work / "data")
    (work / "evals").mkdir()
    shutil.copytree(ROOT / "evals" / "recorded", work / "evals" / "recorded")
    for name in ("answer_key.json", "intel_key.json"):
        shutil.copy(ROOT / "evals" / name, work / "evals" / name)
    shutil.copytree(ROOT / "checklist", work / "checklist")
    done = _run([py, "-c", "import sys; from asa.cli import main; sys.exit(main(['demo']))"], work)
    assert done.returncode == 0, (done.stdout + done.stderr)[-1200:]
    assert "trails: 30 verified, 0 failed" in done.stdout and "Traceback" not in done.stderr
    assert (work / "out" / "console" / "index.html").is_file()
    assert not (ROOT / "build").exists()
