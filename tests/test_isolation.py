import ast
import json
from pathlib import Path

from asa import cli

SRC = Path(__file__).resolve().parents[1] / "src" / "asa"
PRIVATE = ("soc_agent", "soc_mcp", "tools", "agent")  # package names from earlier code by the author, which must never be imported
BANNED = ("subprocess", "socket", "ssl", "urllib", "http", "requests", "httpx", "httpx2", "ftplib", "smtplib", "telnetlib",
          "asyncio", "aiohttp")
ALLOWED = ("urllib.parse",)  # string handling only: no I/O


def modules():
    for path in sorted(SRC.rglob("*.py")):  # every subpackage too (asa.intel and the rest)
        yield path, ast.parse(path.read_text(encoding="utf-8"))


def imported(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module, node
            for alias in node.names:  # "from urllib import request" imports urllib.request
                yield f"{node.module}.{alias.name}", node


def test_no_private_or_network_imports():
    for path, tree in modules():
        for name, _ in imported(tree):
            top = name.split(".")[0]
            assert top not in PRIVATE, (path.name, name)
            assert top not in BANNED or any(name == a or name.startswith(a + ".") for a in ALLOWED), (path.name, name)
            if top == "anthropic":
                assert path.name == "llm.py", (path.name, name)


def test_no_keys_or_environment_in_the_intel_package():
    """Fixture-only enrichment: no environment variable, no key, no network helper anywhere in asa.intel."""
    for path in sorted((SRC / "intel").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in ("environ", "getenv", "urlopen", "create_connection"), (path.name, node.attr)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "api_key" not in node.value.lower() and "_KEY" not in node.value, (path.name, node.value)


def test_exactly_one_client_constructor_in_the_live_branch():
    calls = []
    for path, tree in modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
                if name == "Anthropic":
                    calls.append(path.name)
    assert calls == ["llm.py"]
    tree = ast.parse((SRC / "llm.py").read_text(encoding="utf-8"))
    live = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "live_client")
    inside = [n for n in ast.walk(live) if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "Anthropic"]
    assert len(inside) == 1
    kwargs = {k.arg for k in inside[0].keywords}
    assert kwargs == {"api_key", "base_url", "max_retries"}


def test_no_absolute_path_in_any_run_artifact(repo_dir, monkeypatch, capsys):
    from test_agent import install_live_recording

    install_live_recording(repo_dir)
    monkeypatch.chdir(repo_dir)
    assert cli.main(["investigate", "--alert", "A-007", "--mock"]) == 0
    out = capsys.readouterr().out
    needles = {str(repo_dir), repo_dir.as_posix(), json.dumps(str(repo_dir))[1:-1], str(repo_dir.parent)}
    files = [p for p in (repo_dir / "out").rglob("*") if p.is_file()]
    assert files
    for path in files:
        body = path.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in body, path
    for needle in needles:
        assert needle not in out
