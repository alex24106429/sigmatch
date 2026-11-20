from __future__ import annotations

import json

import pytest

from sigmatch.events import (
    EventParseError,
    ProcessCache,
    parse_event_any,
    parse_event_mapping,
    parse_event_xml,
)


def make_xml(event_id: int, fields: dict[str, str], *, record: int = 42) -> str:
    data = "".join(
        f'<Data Name="{name}">{value}</Data>' for name, value in fields.items()
    )
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}" />
    <EventID>{event_id}</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>{event_id}</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-16T13:45:12.1234567Z" />
    <EventRecordID>{record}</EventRecordID>
    <Correlation />
    <Execution ProcessID="1234" ThreadID="5678" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>TESTHOST</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>{data}</EventData>
</Event>"""


def test_parse_process_create_xml():
    event = parse_event_xml(
        make_xml(
            1,
            {
                "RuleName": "-",
                "UtcTime": "2026-11-16 13:45:12.123",
                "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
                "ProcessId": "4321",
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": r'"C:\Windows\System32\cmd.exe" /c whoami',
                "CurrentDirectory": r"C:\Users\win\\",
                "User": "TESTHOST\\win",
                "ParentImage": r"C:\Windows\explorer.exe",
                "ParentCommandLine": r"C:\Windows\explorer.exe",
                "Hashes": "SHA256=ABC",
                "OriginalFileName": "Cmd.Exe",
            },
        )
    )
    assert event.event_id == 1
    assert event.record_id == 42
    assert event.computer == "TESTHOST"
    assert event.channel == "Microsoft-Windows-Sysmon/Operational"
    assert event.provider == "Microsoft-Windows-Sysmon"
    assert event.timestamp is not None
    assert event.timestamp.year == 2026
    assert event.get("image").endswith("cmd.exe")
    assert event.get("IMAGE").endswith("cmd.exe")
    assert event.get("CommandLine") == r'"C:\Windows\System32\cmd.exe" /c whoami'
    assert event.get("Provider_Name") == "Microsoft-Windows-Sysmon"
    assert event.get("ProviderName") == "Microsoft-Windows-Sysmon"
    assert event.get("EventID") == "1"
    assert event.get("EventRecordID") == "42"
    assert event.get("Security_UserID") == "S-1-5-18"
    assert event.get("TimeCreated") is not None
    assert event.to_output()["Data"]["Image"].endswith("cmd.exe")


def test_parse_process_access_and_dns_xml():
    access = parse_event_xml(
        make_xml(
            10,
            {
                "SourceProcessGUID": "{source}",
                "SourceProcessId": "100",
                "SourceImage": r"C:\tools\source.exe",
                "TargetProcessGUID": "{target}",
                "TargetProcessId": "200",
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x1010",
                "CallTrace": r"C:\Windows\SYSTEM32\ntdll.dll+0x123|UNKNOWN",
            },
        )
    )
    assert access.event_id == 10
    assert access.get("sourceprocessguid") == "{source}"
    assert access.get("TargetProcessGUID") == "{target}"
    assert access.get("GrantedAccess") == "0x1010"

    dns = parse_event_xml(
        make_xml(
            22,
            {
                "QueryName": "example.com",
                "QueryStatus": "0",
                "QueryResults": "93.184.216.34;",
                "Image": r"C:\Windows\System32\ping.exe",
                "ProcessGuid": "{dns}",
                "ProcessId": "300",
            },
        )
    )
    assert dns.get("QueryName") == "example.com"
    assert dns.get("QueryResults") == "93.184.216.34;"


def test_json_flat_and_nested_replay():
    flat = parse_event_any(
        json.dumps(
            {
                "EventID": 1,
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "UtcTime": "2026-11-16 13:45:12.123",
                "Computer": "TESTHOST",
            }
        )
    )
    assert flat.event_id == 1
    assert flat.get("Image").endswith("cmd.exe")
    assert flat.get("Provider_Name") == "Microsoft-Windows-Sysmon"

    nested = parse_event_any(
        json.dumps(
            {
                "Event": {
                    "System": {
                        "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                        "EventID": {"#text": "7"},
                        "EventRecordID": "99",
                        "TimeCreated": {"SystemTime": "2026-11-16T13:45:12.123Z"},
                        "Computer": "TESTHOST",
                        "Channel": "Microsoft-Windows-Sysmon/Operational",
                    },
                    "EventData": [
                        {"@Name": "Image", "#text": r"C:\Windows\System32\cmd.exe"},
                        {"@Name": "ImageLoaded", "#text": r"C:\test\sigma_test.dll"},
                    ],
                }
            }
        )
    )
    assert nested.event_id == 7
    assert nested.record_id == 99
    assert nested.get("ImageLoaded").endswith("sigma_test.dll")


def test_parse_event_any_rejects_garbage():
    with pytest.raises(EventParseError):
        parse_event_any("not xml or json")
    with pytest.raises(EventParseError):
        parse_event_xml("<Event><System></Event>")
    with pytest.raises(EventParseError):
        parse_event_mapping({"NoEventID": 1})


def test_process_cache_enrichment():
    cache = ProcessCache()
    create = parse_event_xml(
        make_xml(
            1,
            {
                "ProcessGuid": "{proc}",
                "ProcessId": "4321",
                "Image": r"C:\tools\test.exe",
                "CommandLine": "test.exe --run",
                "ParentImage": r"C:\Windows\explorer.exe",
                "ParentCommandLine": "explorer.exe",
                "User": "TESTHOST\\win",
            },
        )
    )
    cache.observe(create)
    network = parse_event_xml(
        make_xml(
            3,
            {
                "ProcessGuid": "{proc}",
                "ProcessId": "4321",
                "Image": r"C:\tools\test.exe",
                "DestinationIp": "93.184.216.34",
                "DestinationPort": "443",
            },
        )
    )
    cache.enrich(network)
    assert network.get("CommandLine") == "test.exe --run"
    assert network.get("ParentImage").endswith("explorer.exe")
    assert network.get("ParentCommandLine") == "explorer.exe"

    access = parse_event_xml(
        make_xml(
            10,
            {
                "SourceProcessGuid": "{proc}",
                "SourceProcessId": "4321",
                "SourceImage": r"C:\tools\test.exe",
                "TargetProcessGuid": "{target}",
                "TargetProcessId": "200",
                "TargetImage": r"C:\Windows\System32\lsass.exe",
            },
        )
    )
    cache.enrich(access)
    assert access.get("SourceCommandLine") == "test.exe --run"
    assert access.get("SourceParentImage").endswith("explorer.exe")

    terminate = parse_event_xml(
        make_xml(5, {"ProcessGuid": "{proc}", "ProcessId": "4321", "Image": r"C:\tools\test.exe"})
    )
    cache.enrich(terminate)
    after = parse_event_xml(
        make_xml(3, {"ProcessGuid": "{proc}", "ProcessId": "4321", "Image": r"C:\tools\test.exe"})
    )
    cache.enrich(after)
    assert after.get("CommandLine") is None
