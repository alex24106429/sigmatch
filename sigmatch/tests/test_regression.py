"""Run SigmaHQ's own Sysmon-compatible EVTX/JSON regression samples.

The Sigma repository ships positive samples with an expected match count in
``regression_data/.../info.yml``.  This test uses the same samples against our
matcher.  It is the strongest end-to-end check that our condition/modifier
semantics agree with SigmaHQ.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from sigmatch.events import parse_event_mapping, parse_event_xml
from sigmatch.sources import evtx_events


def _load_events(path: Path, test_type: str):
    if test_type == "evtx":
        for xml in evtx_events(path):
            yield parse_event_xml(xml)
        return

    text = path.read_text(encoding="utf-8")
    if test_type == "json":
        data = json.loads(text)
        objects = data if isinstance(data, list) else [data]
    else:  # ndjson / jsonl
        objects = [json.loads(line) for line in text.splitlines() if line.strip()]
    for obj in objects:
        yield parse_event_mapping(obj)


def test_sigma_regression_samples(real_sigma_result):
    sigma_root = Path(__file__).resolve().parents[2] / "sigma"
    regression_root = sigma_root / "regression_data" / "rules" / "windows"
    if not regression_root.is_dir():
        pytest.skip("SigmaHQ regression data is not available")

    by_id = {rule.id: rule for rule in real_sigma_result.rules}
    checked = 0
    failures: list[str] = []
    skipped = 0

    for info_path in sorted(regression_root.rglob("info.yml")):
        info = yaml.safe_load(info_path.read_text(encoding="utf-8")) or {}
        metadata = info.get("rule_metadata") or []
        if not metadata:
            continue
        rule = by_id.get(metadata[0].get("id"))
        if rule is None:
            skipped += 1
            continue

        for test in info.get("regression_tests_info") or []:
            test_type = test.get("type")
            if test_type not in {"evtx", "json", "ndjson", "jsonl"}:
                continue
            relative_path = test.get("path")
            if not relative_path:
                continue
            sample = sigma_root / relative_path
            if not sample.exists():
                skipped += 1
                continue
            expected = int(test.get("match_count") or 1)
            try:
                count = 0
                for event in _load_events(sample, test_type):
                    if event.event_id in rule.event_ids and rule.matches(event.lookup):
                        count += 1
            except Exception as exc:  # noqa: BLE001 - report as a test failure
                failures.append(f"{relative_path}: ERROR {exc!r} ({rule.title})")
                continue
            checked += 1
            if count < expected:
                failures.append(
                    f"{relative_path}: expected >= {expected}, got {count} ({rule.title})"
                )

    assert checked > 300, f"only {checked} regression samples were exercised"
    assert not failures, "\n".join(failures[:20])
