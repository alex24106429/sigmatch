from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


TOOL_ROOT = Path(__file__).resolve().parents[1]
RULE = """title: Cmd Test Rule
id: 77777777-7777-7777-7777-777777777777
status: test
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
"""


def run_cli(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sigmatch", *args],
        cwd=TOOL_ROOT,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=120,
    )


def test_cli_replay_ndjson(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(RULE, encoding="utf-8")
    events = tmp_path / "events.ndjson"
    events.write_text(
        "\n".join(
            [
                json.dumps({"EventID": 1, "Image": r"C:\Windows\System32\cmd.exe"}),
                json.dumps({"EventID": 1, "Image": r"C:\Windows\System32\powershell.exe"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    proc = run_cli(
        "replay",
        str(events),
        "--rules",
        str(rules),
        "--format",
        "json",
        "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["rule"]["title"] == "Cmd Test Rule"
    assert payload["event"]["EventID"] == 1
    assert payload["event"]["Data"]["Image"].endswith("cmd.exe")


def test_cli_replay_xml_stdin(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(RULE, encoding="utf-8")
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-11-16T13:45:12.123Z" />
    <EventRecordID>10</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>TESTHOST</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c echo test</Data>
  </EventData>
</Event>
"""
    proc = run_cli(
        "replay",
        "-",
        "--input-format",
        "xml",
        "--rules",
        str(rules),
        "--quiet",
        input_text=xml,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Cmd Test Rule" in proc.stdout


def test_cli_validate(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(RULE, encoding="utf-8")
    proc = run_cli("validate", "--rules", str(rules), "--quiet")
    assert proc.returncode == 0, proc.stderr
    assert "Validation OK" in proc.stdout
    assert "Rules loaded: 1" in proc.stdout


def test_cli_validate_reports_rule_errors(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yml").write_text(
        """title: Bad
id: 88888888-8888-8888-8888-888888888888
status: test
level: low
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: cmd.exe
  condition: selection and no_such_selection
""",
        encoding="utf-8",
    )
    proc = run_cli("validate", "--rules", str(rules), "--quiet")
    assert proc.returncode == 1
    assert "unknown selection" in proc.stdout


@pytest.mark.skipif(
    not (Path(__file__).resolve().parents[2] / "sigma" / "rules").is_dir(),
    reason="SigmaHQ rules are not available",
)
def test_cli_replay_real_rule(tmp_path):
    events = tmp_path / "events.ndjson"
    events.write_text(
        json.dumps(
            {
                "EventID": 1,
                "Image": r"C:\Users\Public\notwhoami.exe",
                "OriginalFileName": "whoami.exe",
                "CommandLine": "notwhoami.exe /all",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    sigma = Path(__file__).resolve().parents[2] / "sigma" / "rules"
    proc = run_cli(
        "replay",
        str(events),
        "--rules",
        str(sigma),
        "--format",
        "json",
        "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    alerts = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert any(alert["rule"]["title"] == "Renamed Whoami Execution" for alert in alerts)


def test_cli_replay_enrichment(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(
        """title: Enriched Network Rule
id: 99999999-9999-9999-9999-999999999999
status: test
level: high
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    CommandLine|contains: 'enrich_marker'
  condition: selection
""",
        encoding="utf-8",
    )
    events = tmp_path / "events.ndjson"
    events.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "EventID": 1,
                        "ProcessGuid": "{proc}",
                        "ProcessId": "1234",
                        "Image": r"C:\tools\enrich_test.exe",
                        "CommandLine": "enrich_test.exe --enrich_marker",
                    }
                ),
                json.dumps(
                    {
                        "EventID": 3,
                        "ProcessGuid": "{proc}",
                        "ProcessId": "1234",
                        "Image": r"C:\tools\enrich_test.exe",
                        "DestinationIp": "192.0.2.1",
                        "DestinationPort": "443",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    plain = run_cli("replay", str(events), "--rules", str(rules), "--format", "json", "--quiet")
    assert plain.returncode == 0, plain.stderr
    assert plain.stdout.strip() == ""

    enriched = run_cli(
        "replay", str(events), "--rules", str(rules), "--format", "json", "--quiet", "--enrich"
    )
    assert enriched.returncode == 0, enriched.stderr
    alerts = [json.loads(line) for line in enriched.stdout.splitlines() if line.strip()]
    assert len(alerts) == 1
    assert alerts[0]["rule"]["title"] == "Enriched Network Rule"
    assert alerts[0]["event"]["Data"]["CommandLine"] == "enrich_test.exe --enrich_marker"


def test_cli_replay_auto_detects_multiline_xml(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(RULE, encoding="utf-8")
    xml = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <EventRecordID>11</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>TESTHOST</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
  </EventData>
</Event>
"""
    proc = run_cli("replay", "-", "--rules", str(rules), "--quiet", input_text=xml)
    assert proc.returncode == 0, proc.stderr
    assert "Cmd Test Rule" in proc.stdout


def test_cli_max_events(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(RULE, encoding="utf-8")
    events = tmp_path / "events.ndjson"
    events.write_text(
        "\n".join(
            json.dumps({"EventID": 1, "Image": r"C:\Windows\System32\cmd.exe"})
            for _ in range(5)
        )
        + "\n",
        encoding="utf-8",
    )
    proc = run_cli(
        "replay",
        str(events),
        "--rules",
        str(rules),
        "--format",
        "json",
        "--quiet",
        "--max-events",
        "1",
    )
    assert proc.returncode == 0, proc.stderr
    alerts = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(alerts) == 1
