from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6")

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QStyleFactory

from sigmatch.events import parse_event_mapping, parse_event_xml
from sigmatch.gui import (
    EventTableModel,
    LiveEventRow,
    MainWindow,
    Problem,
    RuleLoader,
    _elevate_self,
    _elevation_command,
    _live_problem,
    choose_style_name,
    event_summary,
    is_admin,
)
from sigmatch.sources import SourceError


RULE_YAML = """title: GUI Test Process Rule
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
description: Matches cmd.exe from the GUI test.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
"""

EVENT_XML = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <EventRecordID>4242</EventRecordID>
    <TimeCreated SystemTime="2026-01-02T03:04:05.1234567Z" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>TESTHOST</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c echo gui_test</Data>
    <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
    <Data Name="User">TESTHOST\win</Data>
  </EventData>
</Event>
"""


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(["sigmatch-tests"])
    style = choose_style_name()
    if style:
        app.setStyle(style)
    yield app


def _write_rule(tmp_path: Path, text: str = RULE_YAML, name: str = "rule.yml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _load(paths):
    loader = RuleLoader([str(path) for path in paths], stop_event=threading.Event())
    result = {}
    progress = []
    loader.progress.connect(progress.append)
    loader.loaded.connect(lambda outcome: result.setdefault("loaded", outcome))
    loader.failed.connect(lambda problem: result.setdefault("failed", problem))
    loader.run()
    return result, progress


def _row(event=None, rules=()) -> LiveEventRow:
    event = event or parse_event_xml(EVENT_XML)
    return LiveEventRow(event=event, rules=tuple(rules), summary=event_summary(event))


def test_choose_style_prefers_windows11(qapp):
    available = {key.lower(): key for key in QStyleFactory.keys()}
    if "windows11" in available:
        expected = available["windows11"]
    elif "windowsvista" in available:
        expected = available["windowsvista"]
    else:
        expected = None
    assert choose_style_name() == expected


def test_choose_style_falls_back(monkeypatch):
    class VistaOnly:
        @staticmethod
        def keys():
            return ["windowsvista", "Fusion"]

    monkeypatch.setattr("sigmatch.gui.QStyleFactory", VistaOnly)
    assert choose_style_name() == "windowsvista"

    class NoWindowsStyle:
        @staticmethod
        def keys():
            return ["Fusion"]

    monkeypatch.setattr("sigmatch.gui.QStyleFactory", NoWindowsStyle)
    assert choose_style_name() is None


def test_banner_retry_and_dismiss(qapp):
    window = MainWindow(["Z:/sigma"], auto_start=False)
    called = []
    try:
        window.show()
        window._banner.show_error(
            Problem("Problem", "Message", "Details"),
            retry=lambda: called.append(True),
        )
        qapp.processEvents()
        assert window._banner.kind == "error"
        window._banner._retry_button.click()
        qapp.processEvents()
        assert called == [True]
        assert window._banner.kind == ""

        window._banner.show_warning(
            Problem("Warning", "Message", "Details"), timeout_ms=0
        )
        qapp.processEvents()
        assert window._banner.kind == "warning"
        window._banner._dismiss_button.click()
        qapp.processEvents()
        assert window._banner.kind == ""
    finally:
        window.close()
        qapp.processEvents()


def test_event_summaries():
    process = parse_event_mapping(
        {
            "EventID": 1,
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        }
    )
    assert event_summary(process) == r"C:\Windows\System32\cmd.exe  cmd.exe /c whoami"

    network = parse_event_mapping(
        {
            "EventID": 3,
            "Image": r"C:\tools\agent.exe",
            "DestinationIp": "192.0.2.10",
            "DestinationPort": "443",
        }
    )
    assert "agent.exe" in event_summary(network)
    assert "192.0.2.10:443" in event_summary(network)

    registry = parse_event_mapping(
        {
            "EventID": 13,
            "TargetObject": r"HKLM\Software\Test\Value",
            "Details": "DWORD (0x00000001)",
        }
    )
    assert "HKLM" in event_summary(registry)
    assert "DWORD" in event_summary(registry)

    dns = parse_event_mapping(
        {"EventID": 22, "QueryName": "example.test", "QueryResults": "192.0.2.1"}
    )
    assert "example.test" in event_summary(dns)
    assert "192.0.2.1" in event_summary(dns)

    empty = parse_event_mapping({"EventID": 99})
    assert event_summary(empty) == "(no event data)"


def test_table_model_rows_and_cap(qapp):
    first = _row(parse_event_mapping({"EventID": 1, "Image": "one.exe"}))
    second = _row(parse_event_mapping({"EventID": 2, "TargetFilename": "two.txt"}))
    third = _row(parse_event_mapping({"EventID": 3, "Image": "three.exe"}))
    model = EventTableModel(max_rows=2)
    model.append_rows([first])
    model.append_rows([second, third])
    assert model.rowCount() == 2
    assert model.row_at(0) is second
    assert model.row_at(1) is third
    assert model.data(model.index(0, 4)) == ""
    assert model.data(model.index(0, 3)) == "-"
    assert "No Sigma rule matched" in model.data(
        model.index(0, 0), role=Qt.ItemDataRole.ToolTipRole
    )


def test_loader_progress_and_match(qapp, tmp_path):
    _write_rule(tmp_path)
    result, progress = _load([tmp_path])
    assert "loaded" in result, result.get("failed")
    outcome = result["loaded"]
    assert len(outcome.ruleset) == 1
    assert len(outcome.files) == 1
    assert any(item.stage == "discovering" for item in progress)
    loading = [item for item in progress if item.stage == "loading"]
    assert loading
    assert loading[0].current == 0
    assert loading[-1].current == loading[-1].total == 1

    event = parse_event_xml(EVENT_XML)
    matches = tuple(outcome.ruleset.match(event.event_id, event.lookup))
    assert [rule.title for rule in matches] == ["GUI Test Process Rule"]


def test_loader_cancellation(qapp, tmp_path):
    _write_rule(tmp_path)
    stop = threading.Event()
    stop.set()
    loader = RuleLoader([str(tmp_path)], stop_event=stop)
    loaded = []
    failed = []
    progress = []
    loader.loaded.connect(loaded.append)
    loader.failed.connect(failed.append)
    loader.progress.connect(progress.append)
    loader.run()
    assert loaded == []
    assert failed == []
    assert progress and progress[0].stage == "discovering"


def test_loader_reports_missing_path(qapp, tmp_path):
    missing = tmp_path / "does-not-exist"
    result, _ = _load([missing])
    assert "failed" in result
    problem = result["failed"]
    assert "not found" in problem.title.lower()
    assert "--rules" in problem.details


def test_loader_reports_no_compatible_rules(qapp, tmp_path):
    _write_rule(
        tmp_path,
        """title: Security Only
id: 22222222-2222-2222-2222-222222222222
status: test
level: high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
  condition: selection
""",
    )
    result, _ = _load([tmp_path])
    assert "failed" in result
    problem = result["failed"]
    assert "No usable Sigma rules" in problem.title


def test_live_problem_guidance():
    denied = _live_problem(
        SourceError("cannot subscribe: (5, 'EvtSubscribe', 'Access is denied.')")
    )
    assert "Access" in denied.title
    assert "administrator" in denied.message.lower()

    missing_dependency = _live_problem(
        SourceError("pywin32 is required for live/EVTX event reading.")
    )
    assert "pywin32" in missing_dependency.message.lower()
    assert "pip install pywin32" in missing_dependency.details

    missing = _live_problem(SourceError("channel was not found"))
    assert "not available" in missing.title
    assert "Sysmon" in missing.message

    generic = _live_problem(SourceError("unexpected failure"))
    assert "stopped" in generic.title.lower()


def test_table_severity_styling(qapp, tmp_path):
    _write_rule(tmp_path)
    result, _ = _load([tmp_path])
    outcome = result["loaded"]
    event = parse_event_xml(EVENT_XML)
    rules = tuple(outcome.ruleset.match(event.event_id, event.lookup))
    model = EventTableModel()
    model.append_rows([_row(event, rules)])
    index = model.index(0, 4)
    background = model.data(index, Qt.ItemDataRole.BackgroundRole)
    foreground = model.data(index, Qt.ItemDataRole.ForegroundRole)
    assert background is not None and background.name() == "#d83b01"
    assert foreground is not None and foreground.name() == "#ffffff"
    assert model.data(index, Qt.ItemDataRole.DisplayRole) == "High"
    assert model.data(model.index(0, 3), Qt.ItemDataRole.DisplayRole) == "1"


def test_main_window_shows_event_details(qapp, tmp_path):
    _write_rule(tmp_path)
    result, _ = _load([tmp_path])
    outcome = result["loaded"]
    event = parse_event_xml(EVENT_XML)
    rules = tuple(outcome.ruleset.match(event.event_id, event.lookup))
    row = _row(event, rules)

    window = MainWindow([str(tmp_path)], auto_start=False)
    try:
        window.show()
        window._ruleset = outcome.ruleset
        window._model.append_rows([row])
        window._table.selectRow(0)
        qapp.processEvents()

        assert window._details_stack.currentIndex() == 1
        assert window._detail_header.text().startswith("Event 1 -")
        assert window._tabs.tabText(0) == "Matched rules (1)"
        assert "GUI Test Process Rule" in window._rules_view.toPlainText()
        assert window._fields_view.rowCount() >= 4
        assert "<Event" in window._raw_view.toPlainText()

        window._banner.show_error(
            Problem("Test problem", "Helpful text", "Technical details"),
            retry=lambda: None,
        )
        qapp.processEvents()
        assert window._banner.kind == "error"
        assert window._banner.isVisible()
        assert window._banner._title.text() == "Test problem"
    finally:
        window.close()
        qapp.processEvents()
    assert window._closing


def test_main_window_loads_rules_in_thread(qapp, tmp_path):
    _write_rule(tmp_path)
    window = MainWindow([str(tmp_path)], auto_start=True)
    try:
        window.show()
        deadline = time.monotonic() + 10
        while (
            window._ruleset is None
            and window._banner.kind != "error"
            and time.monotonic() < deadline
        ):
            qapp.processEvents()
            time.sleep(0.01)
        assert window._ruleset is not None, window._banner._detail.text()
        assert len(window._ruleset) == 1
    finally:
        window.close()
        qapp.processEvents()


def test_elevation_command_quotes_paths():
    executable, parameters, cwd = _elevation_command(["--rules", "Z:\\sigma rules"])
    assert executable == sys.executable
    assert "sigmatch_gui.py" in parameters or "-m sigmatch.gui" in parameters
    assert "Z:\\sigma rules" in parameters or '"Z:\\sigma rules"' in parameters
    assert "--elevation-attempted" in parameters
    assert cwd == os.getcwd()


def test_elevation_success_and_cancel(monkeypatch):
    messages = []
    monkeypatch.setattr("sigmatch.gui._native_message", lambda text, **kwargs: messages.append(text))

    monkeypatch.setattr(
        "sigmatch.gui._shell_execute_runas", lambda *args: (42, 0)
    )
    assert _elevate_self(["--rules", "Z:\\sigma"]) is True
    assert messages == []

    monkeypatch.setattr(
        "sigmatch.gui._shell_execute_runas", lambda *args: (0, 1223)
    )
    assert _elevate_self(["--rules", "Z:\\sigma"]) is False
    assert "cancelled" in messages[-1].lower()
    assert "administrator" in messages[-1].lower()

    monkeypatch.setattr(
        "sigmatch.gui._shell_execute_runas", lambda *args: (0, 5)
    )
    assert _elevate_self(["--rules", "Z:\\sigma"]) is False
    assert "denied" in messages[-1].lower()


def _sysmon_channel_readable() -> bool:
    try:
        import win32evtlog

        handle = win32evtlog.EvtQuery(
            "Microsoft-Windows-Sysmon/Operational",
            win32evtlog.EvtQueryChannelPath,
            "*",
        )
        return handle is not None
    except Exception:
        return False


@pytest.mark.skipif(
    not is_admin() or not _sysmon_channel_readable(),
    reason="live Sysmon access requires an elevated shell and Sysmon",
)
def test_live_window_end_to_end(qapp):
    live_rules = Path(__file__).resolve().parent / "live_rules"
    if not live_rules.is_dir():
        pytest.skip("live rule fixtures are not available")

    window = MainWindow([str(live_rules)], auto_start=True)
    last_trigger = 0.0
    matched_row = None
    try:
        window.show()
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            qapp.processEvents()
            now = time.monotonic()
            if now - last_trigger >= 0.7:
                last_trigger = now
                subprocess.Popen(
                    ["cmd.exe", "/c", "echo", "sigmatch_live_marker"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            for index in range(window._model.rowCount()):
                row = window._model.row_at(index)
                if row is not None and row.match_count:
                    matched_row = index
                    break
            if matched_row is not None:
                break
            if window._banner.kind == "error":
                pytest.fail(
                    window._banner._title.text()
                    + " | "
                    + window._banner._detail.text()
                )
            time.sleep(0.02)

        assert matched_row is not None, "no matched live Sysmon event arrived"
        window._table.selectRow(matched_row)
        qapp.processEvents()
        assert window._details_stack.currentIndex() == 1
        assert window._tabs.tabText(0).startswith("Matched rules (")
        assert window._fields_view.rowCount() > 0
        assert window._model.row_at(matched_row).match_count >= 1
        assert "Live" in window._status_label.text()
    finally:
        window.close()
        qapp.processEvents()
