"""Load the shipped TOML config (the decision table)."""
from __future__ import annotations

import tomllib
from importlib import resources


def load_toml(name: str) -> dict:
    text = resources.files("asa.intel").joinpath("config", name).read_text(encoding="utf-8")
    return tomllib.loads(text)
