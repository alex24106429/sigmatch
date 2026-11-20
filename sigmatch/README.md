# sigmatch

`sigmatch` matches [SigmaHQ](https://github.com/SigmaHQ/sigma) rules against
Microsoft Sysmon events in real time.  It reads the
`Microsoft-Windows-Sysmon/Operational` event log through a Windows Event Log
pull subscription, parses each event's XML, and evaluates the applicable Sigma
detections locally.

It is a matching engine, not a converter: rules are evaluated directly and
alerts are emitted as text or JSONL.

## Features

* Live Sysmon event subscription (`live`), `.evtx` replay (`evtx`), and
  XML/JSON replay (`replay`).
* Loads `sigma/rules` (and optionally the emerging-threats, threat-hunting,
  compliance and DFIR collections).
* Maps Sigma Windows logsource categories to Sysmon event IDs.
* Implements the Sigma condition language used by SigmaHQ:
  `and`, `or`, `not`, parentheses, `1 of ...`, `any of ...`, `all of ...`,
  `them`, and wildcard selection patterns.
* Implements Sigma value modifiers used by the Windows rules: `contains`,
  `startswith`, `endswith`, `all`, `re`, `i`, `cased`, `windash`, `cidr`,
  `base64`, `base64offset`, `fieldref`, `exists`, `lt`/`lte`/`gt`/`gte`,
  `utf16*`, and `expand`.
* Case-insensitive string matching by default; Sigma `*`/`?` wildcards and
  backslash escaping.
* Optional process-creation cache (`--enrich`) that adds
  `CommandLine`/`ParentImage`/`ParentCommandLine` and source/target context to
  events that do not carry those fields (Sigma "addon" fields).
* Optional PyQt6 desktop UI that follows the live feed, shows rule matches,
  and lets you inspect every event.

## Requirements

* Windows 10/11 or Windows Server.
* Python 3.9+ (tested with Python 3.14).
* `PyYAML`:

```powershell
python -m pip install -r requirements.txt
# or install the package (adds a `sigmatch` command)
python -m pip install -e .
```

Live and EVTX reading need `pywin32`. If it is missing, sigmatch installs it
automatically with pip. If Sysmon is not installed, sigmatch downloads it from
Microsoft Sysinternals, installs it with `config/sysmon-sigmatch.xml`, and
starts the service. Those steps need administrator rights, and failures are
reported with manual installation instructions.

Reading the Sysmon channel normally requires an elevated shell.  Sysmon must be
configured to log the event types you want to match.  See
`config/sysmon-sigmatch.xml` for a test-friendly configuration, or set
`SIGMATCH_SYSMON_CONFIG` to use a different configuration file. Set
`SIGMATCH_SYSMON_PATH` to use an existing `Sysmon64.exe`/`Sysmon.exe`.

## Desktop UI

The UI follows the live Sysmon channel from launch until you close the window.
It shows every event, highlights Sigma matches, and opens event fields, matched
rule details, and the raw XML when you click a row.  Rules are loaded in the
background with a progress bar.

Two checkboxes above the event list control the live view.  "Only events with
Sigma matches" is off by default and filters the table to matching events.
"Notify for high/critical matches" is on by default and sends a Windows
notification when a high or critical Sigma rule matches.  Clicking a
notification brings the window forward and selects the matching event.

```powershell
python -m pip install PyQt6
python sigmatch_gui.py --rules Z:\sigma
```

Or install the optional GUI entry point:

```powershell
python -m pip install -e ".[gui]"
sigmatch-gui --rules Z:\sigma
```

The UI requests administrator rights automatically through User Account Control,
because reading `Microsoft-Windows-Sysmon/Operational` requires elevation.  Use
`--no-elevate` only for development; live reading will normally fail without
administrator rights.  If the rules cannot be found or the Sysmon channel is
unavailable, the window shows an inline message with a Retry button.

## Getting the rules

```powershell
git clone --depth 1 https://github.com/SigmaHQ/sigma.git Z:\sigma
```

The default rule location is `./sigma/rules`, then
`<tool dir>/sigma/rules`, then `<tool dir>/../sigma/rules`.  Use `--rules` to
point anywhere explicitly:

```powershell
python -m sigmatch live --rules Z:\sigma --duration 60
```

Passing a Sigma repository root loads `rules` by default.  Add
`--all-rule-sets` to also load `rules-emerging-threats`,
`rules-threat-hunting`, `rules-compliance` and `rules-dfir`.

## Usage

### Live Sysmon

```powershell
# Follow live events for 5 minutes, print human-readable alerts and stats
python -m sigmatch live --rules Z:\sigma --duration 300 --stats

# Include the last 200 events before following live and write JSONL alerts
python -m sigmatch live --rules Z:\sigma --backfill 200 --format json `
    --json-out Z:\alerts.jsonl

# Only medium and above, stable/test rules
python -m sigmatch live --min-level medium --status stable --status test

# Add process-creation context to network/file/image events (Sigma addon fields)
python -m sigmatch live --rules Z:\sigma --enrich --duration 300
```

### Replay an EVTX file

```powershell
wevtutil epl Microsoft-Windows-Sysmon/Operational Z:\sysmon.evtx
python -m sigmatch evtx Z:\sysmon.evtx --rules Z:\sigma --format json --stats
```

### Replay XML or JSON

```powershell
# One or more Sysmon Event XML documents (the output of Get-WinEvent .ToXml())
python -m sigmatch replay events.xml --input-format xml --rules Z:\sigma

# NDJSON field objects, e.g. {"EventID":1,"Image":"...","CommandLine":"..."}
python -m sigmatch replay events.ndjson --input-format ndjson --rules Z:\sigma

# stdin, auto-detected
Get-Content events.ndjson | python -m sigmatch replay - --rules Z:\sigma
```

### Validate the rule set

```powershell
python -m sigmatch validate --rules Z:\sigma --verbose
```

This reports how many rules compiled, how many files were scanned, exceptions,
and the number of rules per Sysmon event ID.  It exits nonzero on compile
errors.

## How logsource mapping works

| Sigma category | Sysmon event IDs |
| --- | --- |
| `process_creation` | 1 |
| `file_change` | 2 |
| `network_connection` | 3 |
| `sysmon_status` | 4 |
| `process_termination` | 5 |
| `driver_load` | 6 |
| `image_load` | 7 |
| `create_remote_thread` | 8 |
| `raw_access_thread`, `raw_access_read` | 9 |
| `process_access` | 10 |
| `file_event` | 11 |
| `registry_add`, `registry_delete` | 12 |
| `registry_set` | 13 |
| `registry_rename` | 14 |
| `registry_event` | 12, 13, 14 |
| `create_stream_hash` | 15 |
| `pipe_created` | 17 |
| `pipe_connected` | 18 |
| `wmi_event` | 19, 20, 21 |
| `dns_query` | 22 |
| `file_delete` | 23, 26 |
| `clipboard_capture` | 24 |
| `process_tampering` | 25 |
| `file_block` | 27, 28 |
| `file_executable_detected` | 29 |
| `sysmon_error` | 255 |

Rules with `service: sysmon` use the `EventID` field in their detection to
choose the Sysmon event type.  Rules for other services (`security`, `system`,
PowerShell, etc.) are skipped because they do not describe Sysmon telemetry.
A small number of generic Windows rules (no category/service) are evaluated
against all Sysmon events.

## Notes and limitations

* Sigma processing pipelines, backend field mappings, and aggregation
  conditions (`| count() > N`) are not applied.  The rules are evaluated as
  written against Sysmon field names.
* Event 3 (network), 7 (image load), 10 (process access), etc. do not contain
  process command lines by default.  Use `--enrich` if you want a process
  cache to add those context fields.  Enrichment is opt-in because it changes
  the meaning of rules that explicitly match a missing `CommandLine`.
* Rule coverage depends on the Sysmon configuration.  If a Sysmon event type
  is not enabled, no matching alert can be generated.
* Sigma string matching is case-insensitive by default; use `|cased` for the
  rare case-sensitive value.  `|re` follows Sigma's case-sensitive default
  unless `|i` is present.
* Loading the full SigmaHQ `rules` tree takes a few seconds (longer over a
  network share).  Live events written while rules are loading are not
  replayed; use `--backfill N` if you need recent history.

## Development

```powershell
python -m pip install -r requirements.txt
python -m pytest -q
```

The test suite includes unit tests for matchers, condition parsing, XML
parsing, the rule loader, and integration tests that replay synthetic Sysmon
events through real SigmaHQ rules.  `tests/live_rules` contains a rule set used
for manual end-to-end checks against a real Sysmon installation.

Validation performed during development:

* 3,164 SigmaHQ rule files scanned, 1,881 Sysmon-applicable rules compiled,
  0 compile errors.
* Extended collections (`rules-emerging-threats`, `rules-threat-hunting`,
  `rules-compliance`, `rules-dfir`): 2,256 rules, 0 compile errors.
* 365 SigmaHQ EVTX regression samples (plus JSON samples) for Sysmon-compatible
  rules matched with the expected counts (0 failures).
* Sysmon 15.22 end-to-end tests (live subscription plus EVTX replay of the
  captured log) matched event IDs 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 13, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 27 and 29.
* Event-ID mapping also covers 6 (driver load), 12, 14, 26, 28 and 255; those
  paths are exercised by unit tests and category mapping validation.
