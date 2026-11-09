import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def repo_dir(tmp_path: Path) -> Path:
    """A copy of the hand-made fixture repo (data/ + evals/answer_key.json) in a temp folder."""
    dest = tmp_path / "repo"
    shutil.copytree(FIXTURES / "repo", dest)
    return dest


@pytest.fixture
def repo(repo_dir):
    from asa.common import Repo
    return Repo(repo_dir)


@pytest.fixture
def dataset(repo):
    from asa.tools import Dataset
    return Dataset(repo)


# The fixture builder (tests/fixtures/build_recorded.py) is importable from tests.
import sys  # noqa: E402

sys.path.insert(0, str(FIXTURES))
