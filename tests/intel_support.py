"""Shared helpers for the intel tests: a copy of the real dataset + recording, and a replay helper (all $0, offline)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RECORDING = "live-20261028"


@pytest.fixture(scope="session")
def real_repo_dir(tmp_path_factory) -> Path:
    """data/ (with the intel fixtures), the answer key and the recorded run, copied to a temp folder."""
    dest = tmp_path_factory.mktemp("real") / "repo"
    shutil.copytree(ROOT / "data", dest / "data")
    (dest / "evals").mkdir()
    shutil.copy(ROOT / "evals" / "answer_key.json", dest / "evals" / "answer_key.json")
    shutil.copytree(ROOT / "evals" / "recorded" / RECORDING, dest / "evals" / "recorded" / RECORDING)
    return dest


@pytest.fixture(scope="session")
def real_repo(real_repo_dir):
    from asa.common import Repo

    return Repo(real_repo_dir)


@pytest.fixture(scope="session")
def real_dataset(real_repo):
    from asa.tools import Dataset

    return Dataset(real_repo)


@pytest.fixture(scope="session")
def replayed(real_repo):
    """alert id -> run folder, for the whole recording replayed once at $0."""
    from asa.agent import investigate
    from asa.llm import ReplayClient

    runs = {}
    for n in range(1, 31):
        alert_id = f"A-{n:03d}"
        client = ReplayClient.from_dir(real_repo.path("evals/recorded", RECORDING, alert_id), RECORDING, require_live=True)
        runs[alert_id], _ = investigate(alert_id, client, real_repo, run_id="20261104T000000Z-mock")
    return runs


def load_key() -> dict:
    return json.loads((ROOT / "evals" / "intel_key.json").read_text(encoding="utf-8"))
