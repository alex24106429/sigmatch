from __future__ import annotations

from pathlib import Path

import pytest

from sigmatch.rules import load_rules


@pytest.fixture(scope="session")
def sigma_rules_path() -> Path:
    path = Path(__file__).resolve().parents[2] / "sigma" / "rules"
    if not path.is_dir():
        pytest.skip("SigmaHQ rules are not available next to the tool")
    return path


@pytest.fixture(scope="session")
def real_sigma_result(sigma_rules_path: Path):
    return load_rules([sigma_rules_path])
