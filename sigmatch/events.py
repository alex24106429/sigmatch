"""Sysmon event parsing, normalisation and optional process enrichment."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


class EventParseError(Exception):
    """Raised when an event XML/JSON document cannot be parsed."""


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first_child(element: ET.Element, local_name: str) -> ET.Element | None:
    for child in list(element):
        if _local(child.tag) == local_name:
            return child
    return None


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Python 3.9/3.10 reject more than six fractional digits; Sysmon
        # commonly emits seven.
        text = re.sub(r"(\.\d{6})\d+", r"\1", text)
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


@dataclass
class SysmonEvent:
    event_id: int
    data: dict[str, str] = field(default_factory=dict)
    record_id: int | None = None
    timestamp: datetime | None = None
    channel: str = SYSMON_CHANNEL
    provider: str = SYSMON_PROVIDER
    computer: str = ""
    raw_xml: str | None = None
    lookup: dict[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.lookup = {key.lower(): value for key, value in self.data.items()}

    def get(self, name: str) -> str | None:
        return self.lookup.get(name.lower())

    def has(self, name: str) -> bool:
        return name.lower() in self.lookup

    def add_field(self, name: str, value: Any, overwrite: bool = False) -> None:
        if not overwrite and self.has(name):
            return
        text = _as_text(value)
        self.data[name] = text
        self.lookup[name.lower()] = text

    def to_output(self) -> dict[str, Any]:
        return {
            "EventID": self.event_id,
            "EventRecordID": self.record_id,
            "UtcTime": self.timestamp.isoformat() if self.timestamp else self.get("UtcTime"),
            "Channel": self.channel,
            "Provider": self.provider,
            "Computer": self.computer,
            "Data": self.data,
        }


def parse_event_xml(xml_text: str | bytes) -> SysmonEvent:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise EventParseError(f"invalid event XML: {exc}") from exc

    system = _first_child(root, "System")
    if system is None:
        raise EventParseError("event XML has no <System> element")

    event_id_text = ""
    event_id_element = _first_child(system, "EventID")
    if event_id_element is not None and event_id_element.text:
        event_id_text = event_id_element.text.strip()
    try:
        event_id = int(event_id_text)
    except ValueError as exc:
        raise EventParseError(f"event XML has invalid EventID {event_id_text!r}") from exc

    record_id: int | None = None
    record_element = _first_child(system, "EventRecordID")
    if record_element is not None and record_element.text:
        try:
            record_id = int(record_element.text.strip())
        except ValueError:
            record_id = None

    timestamp = None
    time_element = _first_child(system, "TimeCreated")
    if time_element is not None:
        timestamp = _parse_timestamp(time_element.attrib.get("SystemTime"))

    computer = ""
    computer_element = _first_child(system, "Computer")
    if computer_element is not None and computer_element.text:
        computer = computer_element.text

    channel = ""
    channel_element = _first_child(system, "Channel")
    if channel_element is not None and channel_element.text:
        channel = channel_element.text

    provider = ""
    provider_element = _first_child(system, "Provider")
    if provider_element is not None:
        provider = provider_element.attrib.get("Name", "")

    data: dict[str, str] = {}
    event_data = _first_child(root, "EventData")
    if event_data is not None:
        for element in event_data.iter():
            if element is event_data:
                continue
            if _local(element.tag) != "Data":
                continue
            name = element.attrib.get("Name")
            if not name:
                continue
            data[name] = element.text if element.text is not None else ""

    # Some providers put fields under <UserData>.  Sysmon normally uses
    # EventData, but supporting this costs little and makes replaying events
    # from other Windows logs less surprising.
    user_data = _first_child(root, "UserData")
    if user_data is not None:
        for element in user_data.iter():
            if element is user_data or not element.attrib.get("Name"):
                continue
            name = element.attrib["Name"]
            data.setdefault(name, element.text if element.text is not None else "")

    event = SysmonEvent(
        event_id=event_id,
        data=data,
        record_id=record_id,
        timestamp=timestamp,
        channel=channel or SYSMON_CHANNEL,
        provider=provider or SYSMON_PROVIDER,
        computer=computer,
        raw_xml=xml_text.decode("utf-8", errors="replace") if isinstance(xml_text, bytes) else xml_text,
    )

    event.add_field("EventID", event_id, overwrite=True)
    if record_id is not None:
        event.add_field("EventRecordID", record_id, overwrite=True)
    event.add_field("Channel", event.channel, overwrite=True)
    event.add_field("Provider_Name", event.provider, overwrite=True)
    event.add_field("ProviderName", event.provider, overwrite=True)
    event.add_field("Computer", event.computer, overwrite=True)
    if timestamp is not None:
        event.add_field("TimeCreated", timestamp.isoformat(), overwrite=True)
        event.add_field(
            "UtcTime",
            timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            overwrite=False,
        )

    # System/Security UserID is how Sigma security rules refer to the SID.
    security = _first_child(system, "Security")
    if security is not None and security.attrib.get("UserID"):
        event.add_field("Security_UserID", security.attrib["UserID"], overwrite=False)

    return event


def _flatten_nested_event(obj: Mapping[str, Any]) -> dict[str, str]:
    """Flatten a Windows ``Event`` JSON object into Sysmon fields."""

    result: dict[str, str] = {}
    event = obj.get("Event", obj)
    if not isinstance(event, Mapping):
        raise EventParseError("JSON event object has no object-valued 'Event' member")
    system = event.get("System")
    if isinstance(system, Mapping):
        for key, value in system.items():
            if isinstance(value, Mapping):
                # e.g. {"@Name": "Microsoft-Windows-Sysmon", "#text": "..."}
                value = value.get("#text", value.get("@Name", ""))
            result[str(key).lstrip("@")] = _as_text(value)
    event_data = event.get("EventData")
    if isinstance(event_data, Mapping):
        for key, value in event_data.items():
            result[str(key).lstrip("@")] = _as_text(value)
    elif isinstance(event_data, list):
        for item in event_data:
            if not isinstance(item, Mapping):
                continue
            name = item.get("Name", item.get("@Name"))
            if name is None:
                continue
            value = item.get("Value", item.get("#text", ""))
            result[str(name)] = _as_text(value)
    return result


def parse_event_mapping(obj: Mapping[str, Any]) -> SysmonEvent:
    if "xml" in obj or "Xml" in obj or "XML" in obj:
        xml_value = obj.get("xml", obj.get("Xml", obj.get("XML")))
        return parse_event_xml(str(xml_value))

    fields = _flatten_nested_event(obj) if "Event" in obj else {
        str(key).lstrip("@"): _as_text(value) for key, value in obj.items()
    }

    lower = {key.lower(): value for key, value in fields.items()}
    if "eventid" not in lower:
        raise EventParseError("JSON event has no EventID field")
    try:
        event_id = int(lower["eventid"])
    except (TypeError, ValueError) as exc:
        raise EventParseError(f"JSON event has invalid EventID {lower['eventid']!r}") from exc

    record_id = None
    if "eventrecordid" in lower:
        try:
            record_id = int(lower["eventrecordid"])
        except ValueError:
            pass

    timestamp = _parse_timestamp(lower.get("utctime") or lower.get("timecreated"))
    data = dict(fields)
    event = SysmonEvent(
        event_id=event_id,
        data=data,
        record_id=record_id,
        timestamp=timestamp,
        channel=lower.get("channel", SYSMON_CHANNEL),
        provider=lower.get("provider_name") or lower.get("providername") or SYSMON_PROVIDER,
        computer=lower.get("computer", ""),
    )
    event.add_field("EventID", event_id, overwrite=True)
    if record_id is not None:
        event.add_field("EventRecordID", record_id, overwrite=True)
    event.add_field("Channel", event.channel, overwrite=True)
    event.add_field("Provider_Name", event.provider, overwrite=True)
    event.add_field("ProviderName", event.provider, overwrite=True)
    event.add_field("Computer", event.computer, overwrite=True)
    if timestamp is not None:
        event.add_field("TimeCreated", timestamp.isoformat(), overwrite=True)
        event.add_field("UtcTime", timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], overwrite=False)
    return event


def parse_event_any(text: str) -> SysmonEvent:
    stripped = text.lstrip("\ufeff").strip()
    if not stripped:
        raise EventParseError("empty event")
    if stripped.startswith("<"):
        return parse_event_xml(stripped)
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise EventParseError(f"event is neither XML nor JSON: {exc}") from exc
    if not isinstance(obj, Mapping):
        raise EventParseError("JSON event must be an object")
    return parse_event_mapping(obj)


# ---------------------------------------------------------------------------
# Optional process-context enrichment
# ---------------------------------------------------------------------------


class ProcessCache:
    """Tiny process-creation cache used to add EDR-style addon fields.

    Sysmon's network/file/registry events reference a process GUID but do not
    repeat CommandLine/ParentImage.  Sigma's Windows rules mark these as
    "addon" fields.  This cache is opt-in (``--enrich``) because enriching
    changes the raw Sysmon semantics, notably for rules that intentionally
    match a missing CommandLine.
    """

    ENRICH_FIELDS = (
        "CommandLine",
        "ParentImage",
        "ParentCommandLine",
        "ParentProcessGuid",
        "ParentProcessId",
        "ParentUser",
        "OriginalFileName",
        "CurrentDirectory",
        "IntegrityLevel",
        "Hashes",
        "Company",
        "Description",
        "Product",
        "FileVersion",
        "User",
        "LogonId",
        "LogonGuid",
        "TerminalSessionId",
    )

    def __init__(self, max_entries: int = 8192) -> None:
        self.max_entries = max_entries
        self._by_guid: OrderedDict[str, dict[str, str]] = OrderedDict()
        self._by_pid: OrderedDict[str, dict[str, str]] = OrderedDict()

    @staticmethod
    def _key(value: str | None) -> str | None:
        return value.casefold() if value else None

    def observe(self, event: SysmonEvent) -> None:
        if event.event_id != 1:
            return
        info: dict[str, str] = {}
        for name in self.ENRICH_FIELDS:
            value = event.get(name)
            if value is not None:
                info[name] = value
        if not info:
            return
        guid = self._key(event.get("ProcessGuid"))
        pid = self._key(event.get("ProcessId"))
        if guid:
            self._by_guid[guid] = info
            self._by_guid.move_to_end(guid)
        if pid:
            self._by_pid[pid] = info
            self._by_pid.move_to_end(pid)
        self._trim()

    def _trim(self) -> None:
        while len(self._by_guid) > self.max_entries:
            self._by_guid.popitem(last=False)
        while len(self._by_pid) > self.max_entries:
            self._by_pid.popitem(last=False)

    def _lookup(self, event: SysmonEvent, guid_field: str, pid_field: str) -> dict[str, str] | None:
        guid = self._key(event.get(guid_field))
        if guid and guid in self._by_guid:
            return self._by_guid[guid]
        pid = self._key(event.get(pid_field))
        if pid and pid in self._by_pid:
            return self._by_pid[pid]
        return None

    def enrich(self, event: SysmonEvent) -> None:
        # Source/target process context for injection-related events.
        if event.event_id in {8, 10}:
            for prefix in ("Source", "Target"):
                info = self._lookup(event, f"{prefix}ProcessGuid", f"{prefix}ProcessId")
                if not info:
                    continue
                for name, value in info.items():
                    event.add_field(f"{prefix}{name}", value, overwrite=False)
                if "ParentImage" in info:
                    event.add_field(f"{prefix}ParentImage", info["ParentImage"], overwrite=False)
                if "ParentCommandLine" in info:
                    event.add_field(
                        f"{prefix}ParentCommandLine", info["ParentCommandLine"], overwrite=False
                    )
            return

        info = self._lookup(event, "ProcessGuid", "ProcessId")
        if not info:
            return
        for name, value in info.items():
            event.add_field(name, value, overwrite=False)

        if event.event_id == 5:
            # Process terminated; drop it after any last enrichment.
            guid = self._key(event.get("ProcessGuid"))
            pid = self._key(event.get("ProcessId"))
            if guid:
                self._by_guid.pop(guid, None)
            if pid:
                self._by_pid.pop(pid, None)
