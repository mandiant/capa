# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Parser for VMRay Function Log text format (flog.txt).

flog.txt is a free download from VMRay (Threat Feed -> Full Report -> Download Function Log).
Format: header lines starting with "#", then Process: blocks containing Region: and Thread:
blocks. Thread blocks contain API trace lines like:
  [0072.750] GetCurrentProcess () returned 0xffffffffffffffff
  [0071.184] RegisterClipboardFormatW (lpszFormat="WM_GETCONTROLTYPE") returned 0xc1dc

See: https://github.com/mandiant/capa/issues/2452
"""

import re
from pathlib import Path
from typing import Any, Optional

from capa.exceptions import UnsupportedFormatError
from capa.features.extractors.vmray.models import (
    Analysis,
    Flog,
    FunctionCall,
    MonitorProcess,
    MonitorThread,
    Param,
    Params,
)

FLOG_TXT_VERSION_HEADER = "# Flog Txt Version 1"

# Matches name=value argument pairs inside an API call's parentheses.
# value may be: "quoted string" (including escaped chars), 0xHEX, decimal, or other token.
_PARAM_RE = re.compile(r'(\w+)=((?:"(?:[^"\\]|\\.)*")|(?:0x[0-9a-fA-F]+)|(?:\d+)|(?:[^,\s]+))')


def _parse_hex_or_decimal(s: str) -> int:
    s = s.strip().strip('"')
    if not s:
        return 0
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def _parse_properties(block: str) -> dict[str, Any]:
    """Parse key = value lines from a Process/Thread/Region block."""
    result: dict[str, Any] = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or " = " not in line:
            continue
        key, _, value = line.partition(" = ")
        key = key.strip()
        value = value.strip()
        if key in ("os_pid", "os_parent_pid", "parent_id", "process_id", "thread_id", "os_tid", "id"):
            result[key] = _parse_hex_or_decimal(value)
        elif key in ("filename", "image_name", "cmd_line", "monitor_reason"):
            result[key] = value.strip('"').replace("\\\\", "\\").strip()
        else:
            result[key] = value
    return result


def _parse_args(args_str: str) -> Optional[Params]:
    """
    Parse an API call's argument string into a Params object.

    Handles: name="quoted string", name=0xHEX, name=DECIMAL.
    String values are modelled as void_ptr + str deref to match the XML extractor convention
    so that String features are correctly yielded by the call feature extractor.
    Numeric values use type unsigned_32bit so that Number features are yielded.
    Symbolic constants (e.g. NULL, TRUE) are skipped; their numeric values are unknown without
    header definitions.

    Returns None if no parseable arguments are present.
    """
    if not args_str.strip():
        return None
    params: list[Param] = []
    for m in _PARAM_RE.finditer(args_str):
        name = m.group(1)
        raw = m.group(2)
        if raw.startswith('"'):
            # String value — model as void_ptr with str deref (matches XML extractor convention)
            str_val = raw[1:-1]
            params.append(
                Param.model_validate({"name": name, "type": "void_ptr", "deref": {"type": "str", "value": str_val}})
            )
        elif re.match(r"^0x[0-9a-fA-F]+$", raw) or raw.isdigit():
            # Numeric value — model as integer so Number features are yielded
            params.append(Param.model_validate({"name": name, "type": "unsigned_32bit", "value": raw}))
        # else: symbolic constant (NULL, INVALID_HANDLE_VALUE, etc.) — skip; value not recoverable
    if not params:
        return None
    return Params.model_validate({"param": params})


def _parse_event(line: str) -> Optional[tuple[str, str, Optional[int]]]:
    """
    Parse one API trace line. Returns (api_name, args_str, return_value) or None.
    Examples:
      [0072.750] GetCurrentProcess () returned 0xffffffffffffffff
      [0071.184] RegisterClipboardFormatW (lpszFormat="WM_GETCONTROLTYPE") returned 0xc1dc
      [0083.567] CoTaskMemFree (pv=0x746aa0)
    """
    line = line.strip()
    if not line.startswith("["):
        return None
    # [timestamp] api_name (args) [returned rv]
    match = re.match(r"\[\s*(\d+)\.(\d+)\]\s+(\S+)\s*\((.*)\)\s*(?:returned\s+(0x[0-9a-fA-F]+|\d+))?", line)
    if not match:
        return None
    _major, _minor, api_name, args, rv = match.groups()
    args = args.strip() if args else ""
    return_value: Optional[int] = None
    if rv:
        return_value = _parse_hex_or_decimal(rv)
    return (api_name, args, return_value)


def _parse_thread_block(
    block: str, thread_props: dict[str, Any]
) -> Optional[tuple[MonitorThread, list[tuple[str, str, Optional[int]]]]]:
    """Parse a Thread: block; return MonitorThread and collect events (caller adds them)."""
    lines = block.splitlines()
    events: list[tuple[str, str, Optional[int]]] = []
    for line in lines:
        if line.strip().startswith("["):
            ev = _parse_event(line)
            if ev:
                events.append(ev)
    thread_id = thread_props.get("thread_id") or thread_props.get("id")
    os_tid = thread_props.get("os_tid", 0)
    process_id = thread_props.get("process_id", 0)
    if thread_id is None:
        return None
    # We return the MonitorThread; events are converted to FunctionCalls by the caller
    return MonitorThread(
        ts=0,
        thread_id=int(thread_id),
        process_id=int(process_id),
        os_tid=int(os_tid) if os_tid else 0,
    ), events


def _parse_process_block(block: str) -> Optional[tuple[MonitorProcess, list[MonitorThread], list[FunctionCall]]]:
    """
    Parse a Process: block. Returns (MonitorProcess, list of MonitorThread, list of FunctionCall) or None.
    """
    # Split by Thread: on its own line (allow optional whitespace)
    parts = re.split(r"\n\s*Thread:\s*\n", block)
    if len(parts) < 2:
        return None  # no Thread: block found
    header_and_regions = parts[0]
    thread_blocks = [p.strip() for p in parts[1:] if p.strip()]

    # First part: Process properties then Region: blocks (use regex for robustness)
    process_props = _parse_properties(re.split(r"\n\s*Region:\s*\n", header_and_regions)[0])
    process_id = process_props.get("id") or process_props.get("process_id")
    if process_id is None:
        return None
    monitor_process = MonitorProcess(
        ts=0,
        process_id=int(process_id),
        image_name=process_props.get("image_name", "").strip('"') or "unknown",
        filename=process_props.get("filename", "").strip('"') or "",
        os_pid=process_props.get("os_pid", 0) or 0,
        monitor_reason=process_props.get("monitor_reason", "analysis_target").strip('"'),
        parent_id=int(process_props.get("parent_id", 0) or 0),
        os_parent_pid=int(process_props.get("os_parent_pid", 0) or 0),
        cmd_line=process_props.get("cmd_line", "").strip('"') or "",
    )

    threads: list[MonitorThread] = []
    function_calls: list[FunctionCall] = []
    fncall_id = 0
    for thread_block in thread_blocks:
        thread_props = _parse_properties(thread_block)
        thread_props["process_id"] = process_id
        parsed = _parse_thread_block(thread_block, thread_props)
        if parsed is None:
            continue
        mon_thread, events = parsed
        threads.append(mon_thread)
        for api_name, args_str, rv in events:
            fncall_id += 1
            # Strip sys_ prefix for Linux kernel calls (match XML behavior)
            if api_name.startswith("sys_"):
                api_name = api_name[4:]
            # use model_validate because FunctionCall's "in" alias clashes with a Python keyword;
            # passing params_in= via __init__ is silently dropped by Pydantic
            function_calls.append(
                FunctionCall.model_validate(
                    {
                        "fncall_id": fncall_id,
                        "process_id": mon_thread.process_id,
                        "thread_id": mon_thread.thread_id,
                        "name": api_name,
                        "in": _parse_args(args_str),
                        "out": None,
                    }
                )
            )

    return (monitor_process, threads, function_calls)


def parse_flog_txt(content: str) -> Flog:
    """
    Parse flog.txt content into the same Flog (Analysis) model used by the XML path.
    """
    # Skip BOM if present; normalize line endings so splits on "Process:\n" / "Thread:\n" work
    if content.startswith("\ufeff"):
        content = content[1:]
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = content.splitlines()
    # Find end of header (first non-# line)
    header_end: Optional[int] = None
    for i, line in enumerate(lines):
        if line.strip() and not line.strip().startswith("#"):
            header_end = i
            break
    if header_end is None:
        header_end = len(lines)
    header = "\n".join(lines[:header_end])
    if FLOG_TXT_VERSION_HEADER not in header:
        raise UnsupportedFormatError(
            "File does not appear to be a VMRay flog.txt (missing '%s')" % FLOG_TXT_VERSION_HEADER
        )
    body = "\n".join(lines[header_end:]).strip()

    # Split by "Process:" on its own line (allow optional whitespace)
    process_blocks = re.split(r"\n\s*Process:\s*\n", body)
    process_blocks = [b.strip() for b in process_blocks if b.strip()]
    # If body started with "Process:\n", first element is the only block and starts with "Process:\n"
    if not process_blocks and body.strip():
        # No split happened (e.g. body is "Process:\nid=..."), treat whole body as one process block
        process_blocks = [body.strip()]
    monitor_processes: list[MonitorProcess] = []
    monitor_threads: list[MonitorThread] = []
    function_calls: list[FunctionCall] = []

    for block in process_blocks:
        # First block may start with "Process:\n" when body began with that line
        if block.lstrip().startswith("Process:"):
            block = block.split("\n", 1)[-1].strip() if "\n" in block else ""
        if not block:
            continue
        result = _parse_process_block(block)
        if result is None:
            continue  # skip malformed process block
        mon_process, threads, calls = result
        monitor_processes.append(mon_process)
        monitor_threads.extend(threads)
        function_calls.extend(calls)

    # Use alias names so Pydantic accepts the lists (Analysis model uses alias= for XML compat)
    analysis = Analysis(
        log_version="1",
        analyzer_version="flog.txt",
        monitor_process=monitor_processes,
        monitor_thread=monitor_threads,
        fncall=function_calls,
    )
    return Flog(analysis=analysis)


def parse_flog_txt_path(path: Path) -> Flog:
    """Parse a flog.txt file from disk."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_flog_txt(text)
