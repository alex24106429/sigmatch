"""Event sources: live Sysmon Event Log subscription, .evtx files and replay."""

from __future__ import annotations

import json
import re
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Iterator, Sequence

from .events import SYSMON_CHANNEL


class SourceError(Exception):
    """Raised when an event source cannot be opened or read."""


def _win32():
    try:
        import win32evtlog  # type: ignore
    except ImportError as exc:  # pragma: no cover - Windows-only dependency
        raise SourceError(
            "pywin32 is required for live/EVTX event reading. "
            "Install it with: python -m pip install pywin32"
        ) from exc
    return win32evtlog


def _render(event) -> str:
    win32evtlog = _win32()
    rendered = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
    if isinstance(rendered, bytes):
        return rendered.decode("utf-8", errors="replace")
    return rendered


def query_backfill(channel: str, count: int, query: str = "*") -> list[str]:
    """Return up to *count* historical events, oldest first."""

    if count <= 0:
        return []
    win32evtlog = _win32()
    try:
        handle = win32evtlog.EvtQuery(
            channel,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            query,
        )
    except Exception as exc:
        raise SourceError(f"cannot query historical events from {channel!r}: {exc}") from exc
    try:
        events = win32evtlog.EvtNext(handle, count, 0, 0)
    except Exception as exc:
        if _is_no_more_events(exc):
            return []
        raise SourceError(f"cannot read historical events from {channel!r}: {exc}") from exc
    return [_render(event) for event in reversed(tuple(events))]


def _is_no_more_events(exc: Exception) -> bool:
    winerror = getattr(exc, "winerror", None)
    text = str(exc).lower()
    return (
        winerror in {259, 4317}
        or "more items" in text
        or "operation identifier is not valid" in text
        or "no more data" in text
    )


def live_events(
    channel: str = SYSMON_CHANNEL,
    *,
    backfill: int = 0,
    query: str = "*",
    stop_event: threading.Event | None = None,
    duration: float | None = None,
    on_subscribe: Callable[[], None] | None = None,
) -> Iterator[str]:
    """Yield Sysmon event XML strings as they are written to the event log.

    A pull subscription (signal event + EvtNext) is used instead of a push
    callback.  This avoids a lingering pywin32 callback thread and lets the
    caller stop cleanly with a duration or stop event.  ``on_subscribe`` (if
    given) runs once the event log subscription is active, just before the
    first event is awaited.
    """

    win32evtlog = _win32()
    try:
        import win32event
    except ImportError as exc:  # pragma: no cover - Windows-only dependency
        raise SourceError("pywin32 win32event support is required") from exc

    signal = win32event.CreateEvent(None, 0, 0, None)
    try:
        subscription = win32evtlog.EvtSubscribe(
            channel,
            win32evtlog.EvtSubscribeToFutureEvents,
            SignalEvent=signal,
            Query=query,
        )
    except Exception as exc:
        raise SourceError(
            f"cannot subscribe to {channel!r}: {exc}. "
            "Is Sysmon installed and is this shell elevated?"
        ) from exc

    if on_subscribe is not None:
        on_subscribe()

    deadline = time.monotonic() + duration if duration else None

    if backfill:
        try:
            for xml in query_backfill(channel, backfill, query):
                yield xml
        except SourceError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise SourceError(f"backfill failed: {exc}") from exc

    while True:
        if stop_event is not None and stop_event.is_set():
            break
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            timeout_ms = max(1, min(500, int(remaining * 1000)))
        else:
            timeout_ms = 500

        try:
            win32event.WaitForSingleObjectEx(signal, timeout_ms, True)
        except Exception as exc:  # pragma: no cover - defensive
            raise SourceError(f"error waiting for event log notification: {exc}") from exc

        # Query even when the wait timed out: depending on the pywin32 and
        # Windows versions, EvtNext may return already-queued events without
        # the signal event having been observed first.
        while True:
            try:
                events = win32evtlog.EvtNext(subscription, 64, 0, 0)
            except Exception as exc:
                if _is_no_more_events(exc):
                    break
                raise SourceError(f"error reading subscribed events: {exc}") from exc
            if not events:
                break
            for event in events:
                yield _render(event)

    # Keep references alive until the generator is closed.
    _ = (signal, subscription)


def evtx_events(path: str | Path, query: str = "*") -> Iterator[str]:
    """Yield all events from an .evtx file, oldest first."""

    win32evtlog = _win32()
    try:
        handle = win32evtlog.EvtQuery(str(path), win32evtlog.EvtQueryFilePath, query)
    except Exception as exc:
        raise SourceError(f"cannot open EVTX file {path!r}: {exc}") from exc

    while True:
        try:
            events = win32evtlog.EvtNext(handle, 128, 0, 0)
        except Exception as exc:
            # pywin32 maps ERROR_NO_MORE_ITEMS / ERROR_INVALID_OPERATION from
            # EvtNext to exceptions on some versions.  Both mean EOF here.
            if _is_no_more_events(exc):
                break
            raise SourceError(f"error reading EVTX file {path!r}: {exc}") from exc
        if not events:
            break
        for event in events:
            yield _render(event)


def _iter_json_array(items: Sequence[object]) -> Iterator[str]:
    for item in items:
        if isinstance(item, str):
            yield item
        else:
            yield json.dumps(item, ensure_ascii=False)


def replay_events(
    path: str | Path | None,
    *,
    input_format: str = "auto",
) -> Iterator[str]:
    """Yield raw event documents from a replay file/stdin.

    ``xml`` accepts one or more XML documents (line-oriented or pretty-printed).
    ``json`` accepts a JSON array, a single JSON object, or newline-delimited
    JSON objects.  ``auto`` detects XML vs JSON and JSON arrays vs NDJSON.
    """

    if path is None or str(path) == "-":
        stream = sys.stdin
        should_close = False
    else:
        stream = open(path, "r", encoding="utf-8-sig", errors="replace")
        should_close = True

    try:
        if input_format == "xml":
            content = stream.read()
            # Split on complete </Event> boundaries so pretty-printed XML
            # works as well as the usual one-line Get-WinEvent output.
            for chunk in re.split(r"(?<=</Event>)", content):
                if chunk.strip():
                    yield chunk.strip()
            return

        if input_format in {"json", "jsonl", "ndjson"}:
            content = stream.read()
            stripped = content.lstrip()
            if input_format != "ndjson" and stripped.startswith("["):
                yield from _iter_json_array(json.loads(content))
                return
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line
            return

        # auto: read enough to detect a JSON array, otherwise stream lines.
        first = ""
        while True:
            char = stream.read(1)
            if not char:
                return
            if not char.isspace():
                first = char
                break
        if first == "[":
            yield from _iter_json_array(json.loads(stream.read()))
            return
        if first == "<":
            # XML documents can span lines; Sysmon's ToXml() normally emits a
            # single line, so line-oriented replay is the pragmatic format.
            pending = first
            for line in stream:
                pending += line
                if pending.rstrip().endswith("</Event>"):
                    yield pending.strip()
                    pending = ""
            if pending.strip():
                yield pending.strip()
            return

        # JSON object(s): re-assemble the first character and stream lines.
        line_buffer = first
        for line in stream:
            line_buffer += line
            stripped = line_buffer.strip()
            if stripped and stripped.startswith("{") and _json_complete(stripped):
                yield stripped
                line_buffer = ""
            elif line_buffer.count("\n") > 1 and stripped and not stripped.startswith("{"):
                line_buffer = ""
        if line_buffer.strip():
            yield line_buffer.strip()
    finally:
        if should_close:
            stream.close()


def _json_complete(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False
