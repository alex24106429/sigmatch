from __future__ import annotations

from pathlib import Path

import pytest

from sigmatch.rules import load_rules


@pytest.fixture(scope="session")
def sigma_rules_path() -> Path:
    project_root = Path(__file__).resolve().parents[1]
    candidates = [
        project_root / "sigma" / "rules",
        project_root.parent / "sigma" / "rules",
    ]
    for path in candidates:
        if path.is_dir():
            return path
    pytest.skip("SigmaHQ rules are not available next to the tool")


@pytest.fixture(scope="session")
def real_sigma_result(sigma_rules_path: Path):
    return load_rules([sigma_rules_path])
