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

"""Tests for VMRay flog.txt parser (#2452)."""

from pathlib import Path

import pytest

import capa.features.insn
import capa.features.common
from capa.exceptions import UnsupportedFormatError
from capa.features.extractors.vmray import flog_txt
from capa.features.extractors.vmray.flog_txt import _parse_args, _parse_event, _parse_hex_or_decimal
from capa.features.extractors.vmray.extractor import VMRayExtractor

# Fixture files live in tests/fixtures/vmray/flog_txt/ (committed to the main repo so they
# are always present in CI without requiring the capa-testfiles submodule).
FLOG_TXT_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vmray" / "flog_txt"


MINIMAL_FLOG_TXT = """
# Log Creation Date: 08.10.2024 18:12:03
# Analyzer Version: 2024.4.1
# Flog Txt Version 1

Process:
id = "1"
os_pid = "0x118c"
os_parent_pid = "0x7d8"
parent_id = "0"
image_name = "svchost.exe"
filename = "c:\\\\users\\\\test\\\\desktop\\\\svchost.exe"
cmd_line = "\\"c:\\\\users\\\\test\\\\desktop\\\\svchost.exe\\" "
monitor_reason = "analysis_target"

Region:
id = "125"
name = "private_0x0000000000010000"

Thread:
id = "1"
os_tid = "0x117c"
 [0072.750] GetCurrentProcess () returned 0xffffffffffffffff
 [0071.184] RegisterClipboardFormatW (lpszFormat="WM_GETCONTROLTYPE") returned 0xc1dc
 [0066.433] CoInitializeEx (pvReserved=0x0, dwCoInit=0x2) returned 0x0
"""


def test_parse_flog_txt_minimal(tmp_path):
    # Write as binary so newlines are exactly \n (avoids Windows \r\n)
    path = tmp_path / "flog.txt"
    path.write_bytes(
        b"# Flog Txt Version 1\n\n"
        b"Process:\n"
        b'id = "1"\n'
        b'os_pid = "0x118c"\n'
        b'image_name = "svchost.exe"\n'
        b'filename = "test.exe"\n'
        b'monitor_reason = "analysis_target"\n'
        b'parent_id = "0"\n'
        b'os_parent_pid = "0"\n'
        b'cmd_line = ""\n\n'
        b"Thread:\n"
        b'id = "1"\n'
        b'os_tid = "0x117c"\n'
        b" [0072.750] GetCurrentProcess () returned 0xffffffffffffffff\n"
    )
    flog = flog_txt.parse_flog_txt_path(path)
    assert flog.analysis.log_version == "1"
    assert len(flog.analysis.monitor_processes) == 1
    proc = flog.analysis.monitor_processes[0]
    assert proc.image_name == "svchost.exe"
    assert proc.process_id == 1
    assert proc.os_pid == 0x118C
    assert len(flog.analysis.monitor_threads) == 1
    thread = flog.analysis.monitor_threads[0]
    assert thread.thread_id == 1
    assert thread.process_id == 1
    assert len(flog.analysis.function_calls) == 1
    assert flog.analysis.function_calls[0].name == "GetCurrentProcess"


def test_parse_flog_txt_rejects_wrong_header():
    with pytest.raises(UnsupportedFormatError, match="does not appear to be a VMRay flog.txt"):
        flog_txt.parse_flog_txt("not a flog\nProcess:\nid = 1\n")


def test_parse_flog_txt_sys_prefix_stripped(tmp_path):
    # Linux kernel calls start with sys_; parser should strip for consistency with XML
    path = tmp_path / "flog.txt"
    path.write_bytes(
        b"# Flog Txt Version 1\n\n"
        b'Process:\nid = "1"\nos_pid = "0x1000"\nparent_id = "0"\nos_parent_pid = "0"\n'
        b'image_name = "sample"\nfilename = "x"\ncmd_line = ""\nmonitor_reason = "a"\n\n'
        b'Thread:\nid = "1"\nos_tid = "0x2000"\n [0001.000] sys_time () returned 0x0\n'
    )
    flog = flog_txt.parse_flog_txt_path(path)
    assert len(flog.analysis.function_calls) == 1
    assert flog.analysis.function_calls[0].name == "time"


def test_vmray_analysis_from_flog_txt(tmp_path):
    path = tmp_path / "flog.txt"
    path.write_bytes(MINIMAL_FLOG_TXT.encode("utf-8").replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
    from capa.features.extractors.vmray import VMRayAnalysis

    analysis = VMRayAnalysis.from_flog_txt(path)
    assert analysis.submission_name == "flog.txt"
    assert analysis.submission_type == "unknown"
    assert analysis.submission_meta is not None
    assert analysis.submission_static is None
    assert len(analysis.monitor_processes) == 1
    assert len(analysis.monitor_process_calls) >= 1


def test_vmray_extractor_from_flog_txt(tmp_path):
    from capa.features.address import NO_ADDRESS

    path = tmp_path / "flog.txt"
    path.write_bytes(MINIMAL_FLOG_TXT.encode("utf-8").replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
    ext = VMRayExtractor.from_flog_txt(path)
    assert ext.get_base_address() is NO_ADDRESS  # no base address from flog.txt
    procs = list(ext.get_processes())
    assert len(procs) == 1
    threads = list(ext.get_threads(procs[0]))
    assert len(threads) == 1
    calls = list(ext.get_calls(procs[0], threads[0]))
    assert len(calls) == 3


def test_parse_flog_txt_args_parsed(tmp_path):
    """API call arguments are parsed into Param objects for feature extraction."""
    path = tmp_path / "flog.txt"
    path.write_bytes(
        b"# Flog Txt Version 1\n\n"
        b'Process:\nid = "1"\nos_pid = "0x1000"\nparent_id = "0"\nos_parent_pid = "0"\n'
        b'image_name = "sample"\nfilename = "x.exe"\ncmd_line = ""\nmonitor_reason = "a"\n\n'
        b'Thread:\nid = "1"\nos_tid = "0x2000"\n'
        b' [0001.000] CreateFile (lpFileName="test.exe", dwDesiredAccess=0x80000000) returned 0x4\n'
        b" [0002.000] VirtualAlloc (lpAddress=0x0, dwSize=4096) returned 0x10000\n"
        b" [0003.000] GetCurrentProcess () returned 0xffffffffffffffff\n"
    )
    flog = flog_txt.parse_flog_txt_path(path)
    calls = flog.analysis.function_calls

    # CreateFile: string param and numeric param
    create_file = calls[0]
    assert create_file.name == "CreateFile"
    assert create_file.params_in is not None
    params = {p.name: p for p in create_file.params_in.params}
    assert "lpFileName" in params
    assert params["lpFileName"].deref is not None
    assert params["lpFileName"].deref.value == "test.exe"
    assert "dwDesiredAccess" in params
    assert params["dwDesiredAccess"].value == "0x80000000"

    # VirtualAlloc: two numeric params
    virtual_alloc = calls[1]
    assert virtual_alloc.params_in is not None
    va_params = {p.name: p for p in virtual_alloc.params_in.params}
    assert va_params["lpAddress"].value == "0x0"
    assert va_params["dwSize"].value == "4096"

    # no-arg call: params_in should be None
    get_proc = calls[2]
    assert get_proc.name == "GetCurrentProcess"
    assert get_proc.params_in is None


# ---------------------------------------------------------------------------
# Fixture-based feature-presence tests
# ---------------------------------------------------------------------------
# These tests load the realistic flog.txt fixtures from tests/fixtures/vmray/flog_txt/
# and verify that the extractor yields the expected capa features.  They act as
# regression tests for the parser — especially the string-argument parsing path,
# which is brittle — and mirror the pattern used by test_vmray_features.py.


def _collect_all_call_features(ext: VMRayExtractor) -> set:
    """Collect every feature emitted at the call scope across all processes."""
    features = set()
    for ph in ext.get_processes():
        for th in ext.get_threads(ph):
            for ch in ext.get_calls(ph, th):
                for feature, addr in ext.extract_call_features(ph, th, ch):
                    features.add(feature)
    return features


def _collect_call_features_for_process(ext: VMRayExtractor, image_name: str) -> set:
    """Collect call-scope features only for the process whose image_name matches."""
    features = set()
    for ph in ext.get_processes():
        if ph.inner.image_name != image_name:
            continue
        for th in ext.get_threads(ph):
            for ch in ext.get_calls(ph, th):
                for feature, addr in ext.extract_call_features(ph, th, ch):
                    features.add(feature)
    return features


# --- windows_apis.flog.txt ---------------------------------------------------


@pytest.fixture(scope="module")
def windows_apis_extractor():
    path = FLOG_TXT_FIXTURES / "windows_apis.flog.txt"
    return VMRayExtractor.from_flog_txt(path)


def test_windows_flog_txt_process_count(windows_apis_extractor):
    """Two processes are described in windows_apis.flog.txt."""
    procs = list(windows_apis_extractor.get_processes())
    assert len(procs) == 2


def test_windows_flog_txt_api_features(windows_apis_extractor):
    """Common Win32 API names are yielded as API features."""
    features = _collect_all_call_features(windows_apis_extractor)
    for api_name in (
        "CreateFileW",
        "RegOpenKeyExW",
        "InternetOpenW",
        "InternetConnectW",
        "VirtualAlloc",
        "CreateMutexW",
        "LoadLibraryW",
        "CreateProcessW",
        "HttpOpenRequestW",
        "WinHttpConnect",
        "GetAddrInfoW",
        "GetComputerNameW",
    ):
        assert capa.features.insn.API(api_name) in features, f"API({api_name!r}) not found"


def test_windows_flog_txt_string_args(windows_apis_extractor):
    """String arguments are extracted and backslash-escaping is correctly unwound."""
    features = _collect_all_call_features(windows_apis_extractor)
    for expected_string in (
        # CreateFileW lpFileName (double-backslash in flog → single backslash in feature)
        "C:\\Users\\test\\Documents\\config.ini",
        # RegOpenKeyExW lpSubKey
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        # InternetOpenW lpszAgent
        "Mozilla/5.0 (Windows NT 10.0)",
        # InternetConnectW lpszServerName
        "evil.example.com",
        # CreateMutexW lpName
        "Global\\MyMutex12345",
        # LoadLibraryW lpLibFileName
        "kernel32.dll",
        # HttpOpenRequestW verb and path
        "GET",
        "/beacon",
        # WinHttpConnect pswzServerName
        "c2.example.org",
        # WinHttpOpenRequest verb
        "POST",
        # GetComputerNameW result (child process)
        "DESKTOP-TEST01",
    ):
        assert capa.features.common.String(expected_string) in features, f"String({expected_string!r}) not found"


def test_windows_flog_txt_string_double_backslash_absent(windows_apis_extractor):
    """Double-escaped backslashes (as they appear in the raw flog.txt) must NOT appear in features."""
    features = _collect_all_call_features(windows_apis_extractor)
    # The raw flog.txt content has C:\\Users\\...; the extractor must normalise to single backslash
    assert capa.features.common.String("C:\\\\Users\\\\test\\\\Documents\\\\config.ini") not in features


def test_windows_flog_txt_number_args(windows_apis_extractor):
    """Numeric arguments are extracted as Number features."""
    features = _collect_all_call_features(windows_apis_extractor)
    # VirtualAlloc dwSize
    assert capa.features.insn.Number(4096) in features
    # VirtualAlloc flAllocationType
    assert capa.features.insn.Number(0x3000) in features
    # VirtualAlloc flProtect
    assert capa.features.insn.Number(0x40) in features
    # CreateFileW dwDesiredAccess
    assert capa.features.insn.Number(0x80000000) in features


def test_windows_flog_txt_child_process(windows_apis_extractor):
    """The spawned child process (cmd.exe) is present and has its own API calls."""
    features = _collect_call_features_for_process(windows_apis_extractor, "cmd.exe")
    assert capa.features.insn.API("NtQueryInformationProcess") in features
    assert capa.features.insn.API("GetUserNameW") in features
    # GetUserNameW lpBuffer string
    assert capa.features.common.String("test") in features


# --- linux_syscalls.flog.txt -------------------------------------------------


@pytest.fixture(scope="module")
def linux_syscalls_extractor():
    path = FLOG_TXT_FIXTURES / "linux_syscalls.flog.txt"
    return VMRayExtractor.from_flog_txt(path)


def test_linux_flog_txt_sys_prefix_stripped(linux_syscalls_extractor):
    """sys_ prefix is stripped from all Linux syscall names."""
    features = _collect_all_call_features(linux_syscalls_extractor)
    # Every syscall name should appear WITHOUT the sys_ prefix
    for stripped_name in (
        "read",
        "write",
        "open",
        "connect",
        "socket",
        "execve",
        "fork",
        "getuid",
        "setuid",
        "chmod",
        "unlink",
        "time",
        "ptrace",
        "prctl",
        "mmap",
        "mprotect",
        "munmap",
        "bind",
        "listen",
        "accept",
        "sendto",
        "recvfrom",
    ):
        assert capa.features.insn.API(stripped_name) in features, f"API({stripped_name!r}) not found after stripping"


def test_linux_flog_txt_sys_prefix_not_present(linux_syscalls_extractor):
    """sys_-prefixed names must NOT appear in features (only the stripped form)."""
    features = _collect_all_call_features(linux_syscalls_extractor)
    assert capa.features.insn.API("sys_open") not in features
    assert capa.features.insn.API("sys_execve") not in features


def test_linux_flog_txt_string_args(linux_syscalls_extractor):
    """String path arguments from Linux syscalls are extracted correctly."""
    features = _collect_all_call_features(linux_syscalls_extractor)
    assert capa.features.common.String("/etc/passwd") in features
    assert capa.features.common.String("/bin/sh") in features
    assert capa.features.common.String("/tmp/backdoor") in features
    assert capa.features.common.String("/tmp/.hidden") in features


# --- string_edge_cases.flog.txt -----------------------------------------------


@pytest.fixture(scope="module")
def string_edge_cases_extractor():
    path = FLOG_TXT_FIXTURES / "string_edge_cases.flog.txt"
    return VMRayExtractor.from_flog_txt(path)


def test_edge_case_paths_with_spaces(string_edge_cases_extractor):
    """File paths containing spaces are parsed correctly."""
    features = _collect_all_call_features(string_edge_cases_extractor)
    assert capa.features.common.String("C:\\path with spaces\\file name.txt") in features


def test_edge_case_unc_path(string_edge_cases_extractor):
    """UNC paths (\\server\\share) are parsed correctly."""
    features = _collect_all_call_features(string_edge_cases_extractor)
    assert capa.features.common.String("\\\\server\\share\\document.docx") in features


def test_edge_case_url_string(string_edge_cases_extractor):
    """Full URL strings are preserved as-is."""
    features = _collect_all_call_features(string_edge_cases_extractor)
    assert capa.features.common.String("https://c2.example.com/payload.bin") in features


def test_edge_case_registry_key(string_edge_cases_extractor):
    """Registry key paths are normalised to single backslashes."""
    features = _collect_all_call_features(string_edge_cases_extractor)
    assert capa.features.common.String("Software\\Microsoft\\Windows NT\\CurrentVersion") in features


def test_edge_case_numeric_args(string_edge_cases_extractor):
    """Numeric arguments from edge-case calls are extracted."""
    features = _collect_all_call_features(string_edge_cases_extractor)
    # send() len=256
    assert capa.features.insn.Number(256) in features
    # recv() len=4096
    assert capa.features.insn.Number(4096) in features
    # WriteProcessMemory nSize=4096
    assert capa.features.insn.Number(4096) in features


# ---------------------------------------------------------------------------
# _parse_hex_or_decimal parametric tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("0", 0),
        ("1", 1),
        ("255", 255),
        ("4294967295", 4294967295),
        ("0x0", 0),
        ("0xff", 255),
        ("0xFF", 255),
        ("0xDEADbeef", 0xDEADBEEF),
        ("0xffffffffffffffff", 0xFFFFFFFFFFFFFFFF),
        ("0x80070005", 0x80070005),
        # leading/trailing whitespace is stripped
        ("  0x10  ", 0x10),
        # quoted values are unquoted before parsing
        ('"0x20"', 0x20),
        # empty string → 0
        ("", 0),
        # negative decimal (Python int() accepts it)
        ("-1", -1),
    ],
)
def test_parse_hex_or_decimal_valid(raw, expected):
    assert _parse_hex_or_decimal(raw) == expected


@pytest.mark.parametrize("raw", ["NULL", "TRUE", "FALSE", "INVALID_HANDLE_VALUE", "abc"])
def test_parse_hex_or_decimal_invalid_raises(raw):
    with pytest.raises((ValueError, TypeError)):
        _parse_hex_or_decimal(raw)


# ---------------------------------------------------------------------------
# _parse_event parametric tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line, expected_api, expected_rv",
    [
        # basic no-arg call with hex return value
        ("[0072.750] GetCurrentProcess () returned 0xffffffffffffffff", "GetCurrentProcess", 0xFFFFFFFFFFFFFFFF),
        # uppercase hex return value (mixed case)
        ("[0001.000] GetCurrentProcess () returned 0xFFFFFFFF", "GetCurrentProcess", 0xFFFFFFFF),
        # HRESULT-style error code
        ("[0001.010] DeleteFileW () returned 0x80070005", "DeleteFileW", 0x80070005),
        # no return value at all (line ends after closing paren)
        ("[0083.567] CoTaskMemFree (pv=0x746aa0)", "CoTaskMemFree", None),
        # decimal return value
        ("[0001.003] ExitProcess (uExitCode=0) returned 0", "ExitProcess", 0),
        # leading zeros in timestamp major/minor
        ("[0001.000] NtCreateFile () returned 0x0", "NtCreateFile", 0),
        # large timestamp
        ("[9999.999] LongRunningOp () returned 0x1", "LongRunningOp", 1),
    ],
)
def test_parse_event_valid(line, expected_api, expected_rv):
    result = _parse_event(line)
    assert result is not None
    api_name, _args, rv = result
    assert api_name == expected_api
    assert rv == expected_rv


@pytest.mark.parametrize(
    "line",
    [
        # does not start with '['
        "GetCurrentProcess () returned 0x1",
        # comment / header line
        "# Flog Txt Version 1",
        # blank line
        "",
        # property line (key = value)
        'id = "1"',
        # bracket never closed
        "[0001.000 GetCurrentProcess () returned 0x1",
        # section header
        "Process:",
        "Thread:",
        "Region:",
    ],
)
def test_parse_event_rejects_non_event_lines(line):
    assert _parse_event(line) is None


# ---------------------------------------------------------------------------
# _parse_args parametric tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args_str, expected_names",
    [
        # empty / whitespace-only → None
        ("", None),
        ("   ", None),
        # only symbolic constants (NULL, TRUE) → no parseable params → None
        ("lpszProxyName=NULL, lpszProxyBypass=NULL", None),
        # string arg only
        ('lpszAgent="WinInet"', ["lpszAgent"]),
        # numeric hex arg
        ("dwDesiredAccess=0x80000000", ["dwDesiredAccess"]),
        # numeric decimal arg
        ("dwLen=16", ["dwLen"]),
        # mixed: string + hex + decimal + symbolic (symbolic skipped)
        ('lpFileName="test.exe", dwAccess=0x80000000, count=4096, hTemplate=NULL', ["lpFileName", "dwAccess", "count"]),
        # mixed-case hex is accepted
        ("addr=0xDEADbeef", ["addr"]),
    ],
)
def test_parse_args_param_names(args_str, expected_names):
    result = _parse_args(args_str)
    if expected_names is None:
        assert result is None
    else:
        assert result is not None
        names = [p.name for p in result.params]
        assert names == expected_names


def test_parse_args_string_value_stored_in_deref():
    result = _parse_args('lpFileName="hello.txt"')
    assert result is not None
    assert len(result.params) == 1
    p = result.params[0]
    assert p.type_ == "void_ptr"
    assert p.deref is not None
    assert p.deref.type_ == "str"
    assert p.deref.value == "hello.txt"


def test_parse_args_numeric_type():
    result = _parse_args("dwSize=4096, hKey=0x80000001")
    assert result is not None
    names = {p.name: p for p in result.params}
    assert names["dwSize"].type_ == "unsigned_32bit"
    assert names["dwSize"].value == "4096"
    assert names["hKey"].type_ == "unsigned_32bit"
    assert names["hKey"].value == "0x80000001"


# ---------------------------------------------------------------------------
# Malformed-input resilience tests
# ---------------------------------------------------------------------------


_HEADER = b"# Flog Txt Version 1\n\n"
_PROCESS_HEADER = (
    b"Process:\n"
    b'id = "1"\n'
    b'os_pid = "0x1000"\n'
    b'parent_id = "0"\n'
    b'os_parent_pid = "0"\n'
    b'image_name = "sample.exe"\n'
    b'filename = "sample.exe"\n'
    b'cmd_line = ""\n'
    b'monitor_reason = "analysis_target"\n\n'
)
_THREAD_HEADER = b'Thread:\nid = "1"\nos_tid = "0x2000"\n'


@pytest.mark.parametrize(
    "extra_lines",
    [
        # completely garbled event lines are silently skipped
        b"not a valid event line\n",
        b"[broken bracket\n",
        b"[0001.000 missing closing bracket] Func () returned 0x1\n",
        # comment inside thread block is skipped
        b"# stray comment\n [0001.000] GetCurrentProcess () returned 0x1\n",
        # blank lines inside thread block
        b"\n\n [0001.000] GetCurrentProcess () returned 0x1\n",
    ],
)
def test_malformed_event_lines_do_not_crash(tmp_path, extra_lines):
    path = tmp_path / "flog.txt"
    path.write_bytes(_HEADER + _PROCESS_HEADER + _THREAD_HEADER + extra_lines)
    flog = flog_txt.parse_flog_txt_path(path)
    assert flog.analysis.log_version == "1"


def test_process_block_without_thread_is_skipped(tmp_path):
    path = tmp_path / "flog.txt"
    path.write_bytes(_HEADER + b"Process:\n" + b'id = "1"\nos_pid = "0x1000"\nimage_name = "x.exe"\n')
    flog = flog_txt.parse_flog_txt_path(path)
    assert len(flog.analysis.monitor_processes) == 0


def test_bom_prefix_is_accepted(tmp_path):
    path = tmp_path / "flog.txt"
    path.write_bytes(b"\xef\xbb\xbf" + _HEADER + _PROCESS_HEADER + _THREAD_HEADER)
    flog = flog_txt.parse_flog_txt_path(path)
    assert len(flog.analysis.monitor_processes) == 1


# ---------------------------------------------------------------------------
# format_variance.flog.txt — real-world format diversity fixture
# ---------------------------------------------------------------------------
# This fixture exercises: zero-padded hex IDs, decimal-only arguments alongside
# symbolic constants, mixed-case hex return values, multiple threads in one
# process, HRESULT-style error codes as return values, and no-return-value calls.


@pytest.fixture(scope="module")
def format_variance_extractor():
    path = FLOG_TXT_FIXTURES / "format_variance.flog.txt"
    return VMRayExtractor.from_flog_txt(path)


def test_format_variance_process_and_thread_count(format_variance_extractor):
    procs = list(format_variance_extractor.get_processes())
    assert len(procs) == 2
    thread_counts = [len(list(format_variance_extractor.get_threads(p))) for p in procs]
    # first process has two threads, second has one
    assert sorted(thread_counts) == [1, 2]


def test_format_variance_leading_zero_pid_parsed(format_variance_extractor):
    procs = list(format_variance_extractor.get_processes())
    pids = {p.inner.pid for p in procs}
    # os_pid = "0x00000ABC" → 0xABC = 2748
    assert 0xABC in pids


def test_format_variance_api_features(format_variance_extractor):
    features = _collect_all_call_features(format_variance_extractor)
    for api_name in (
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "MoveFileExW",
        "RegOpenKeyExW",
        "RegSetValueExW",
        "CryptAcquireContextW",
        "CryptGenRandom",
        "CryptEncrypt",
        "InternetOpenW",
        "InternetOpenUrlW",
        "CreateProcessW",
        "FindFirstFileW",
        "FindNextFileW",
        "NtQuerySystemInformation",
        "OpenProcess",
        "CloseHandle",
        "WaitForSingleObject",
        "ExitProcess",
    ):
        assert capa.features.insn.API(api_name) in features, f"API({api_name!r}) not found"


def test_format_variance_string_args(format_variance_extractor):
    features = _collect_all_call_features(format_variance_extractor)
    for expected in (
        "C:\\Users\\victim\\Documents\\important.docx",
        "C:\\Users\\victim\\Documents\\important.docx.locked",
        "C:\\Users\\victim\\Documents\\spreadsheet.xlsx",
        "C:\\Users\\victim\\Documents\\spreadsheet.xlsx.locked",
        "C:\\Users\\victim\\README_DECRYPT.txt",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "WindowsDefender",
        "C:\\Users\\victim\\Desktop\\ransomware.exe",
        "Mozilla/4.0 (compatible; MSIE 8.0)",
        "http://ransom.example.com/key?id=ABCDEF0123456789",
        "vssadmin.exe delete shadows /all /quiet",
    ):
        assert capa.features.common.String(expected) in features, f"String({expected!r}) not found"


def test_format_variance_decimal_only_numeric_args(format_variance_extractor):
    features = _collect_all_call_features(format_variance_extractor)
    # RegOpenKeyExW: hKey=2147483650 (decimal), ulOptions=0, samDesired=131097 (decimal)
    assert capa.features.insn.Number(2147483650) in features
    assert capa.features.insn.Number(131097) in features
    # CryptAcquireContextW: dwProvType=24 (decimal)
    assert capa.features.insn.Number(24) in features
    # WaitForSingleObject: dwMilliseconds=4294967295 (decimal INFINITE)
    assert capa.features.insn.Number(4294967295) in features


def test_format_variance_mixed_case_hex_args(format_variance_extractor):
    features = _collect_all_call_features(format_variance_extractor)
    # CryptAcquireContextW dwFlags=0xF0000000 (uppercase hex digits in fixture)
    assert capa.features.insn.Number(0xF0000000) in features


def test_format_variance_no_returnvalue_calls_parsed(format_variance_extractor):
    features = _collect_all_call_features(format_variance_extractor)
    # CoTaskMemFree and GetSystemInfo have no "returned" clause in the fixture
    assert capa.features.insn.API("CoTaskMemFree") in features
    assert capa.features.insn.API("GetSystemInfo") in features


def test_format_variance_child_process_present(format_variance_extractor):
    features = _collect_call_features_for_process(format_variance_extractor, "vssadmin.exe")
    assert capa.features.insn.API("NtQuerySystemInformation") in features
    assert capa.features.insn.API("OpenProcess") in features


# ---------------------------------------------------------------------------
# crlf_endings.flog.txt — Windows CRLF line endings
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def crlf_extractor():
    path = FLOG_TXT_FIXTURES / "crlf_endings.flog.txt"
    return VMRayExtractor.from_flog_txt(path)


def test_crlf_process_parsed(crlf_extractor):
    procs = list(crlf_extractor.get_processes())
    assert len(procs) == 1
    assert procs[0].inner.image_name == "downloader.exe"


def test_crlf_api_features(crlf_extractor):
    features = _collect_all_call_features(crlf_extractor)
    for api_name in (
        "InternetOpenA",
        "InternetConnectA",
        "HttpOpenRequestA",
        "HttpSendRequestA",
        "InternetReadFile",
        "CreateFileA",
        "WriteFile",
        "WinExec",
    ):
        assert capa.features.insn.API(api_name) in features, f"API({api_name!r}) not found"


def test_crlf_string_args(crlf_extractor):
    features = _collect_all_call_features(crlf_extractor)
    assert capa.features.common.String("WinInet") in features
    assert capa.features.common.String("payload.example.com") in features
    assert capa.features.common.String("GET") in features
    assert capa.features.common.String("/stage2.bin") in features
    assert capa.features.common.String("C:\\Windows\\Temp\\svchost32.exe") in features


# ---------------------------------------------------------------------------
# Round-trip test: parse → extract features → verify counts and spot-checks
# ---------------------------------------------------------------------------


def test_round_trip_feature_count(tmp_path):
    path = tmp_path / "flog.txt"
    path.write_bytes(
        b"# Flog Txt Version 1\n\n"
        b"Process:\n"
        b'id = "1"\nos_pid = "0x1000"\nparent_id = "0"\nos_parent_pid = "0"\n'
        b'image_name = "sample.exe"\nfilename = "sample.exe"\ncmd_line = ""\n'
        b'monitor_reason = "analysis_target"\n\n'
        b"Thread:\n"
        b'id = "1"\nos_tid = "0x2000"\n'
        b' [0001.000] CreateFileW (lpFileName="secret.txt", dwDesiredAccess=0x80000000) returned 0x4\n'
        b" [0001.001] ReadFile (hFile=0x4, lpBuffer=0x5000, nNumberOfBytesToRead=512) returned 0x1\n"
        b" [0001.002] CloseHandle (hObject=0x4) returned 0x1\n"
        b" [0001.003] GetCurrentProcess () returned 0xffffffffffffffff\n"
    )
    ext = VMRayExtractor.from_flog_txt(path)
    procs = list(ext.get_processes())
    assert len(procs) == 1

    threads = list(ext.get_threads(procs[0]))
    assert len(threads) == 1

    calls = list(ext.get_calls(procs[0], threads[0]))
    assert len(calls) == 4

    features = _collect_all_call_features(ext)

    # spot-check: API names
    assert capa.features.insn.API("CreateFileW") in features
    assert capa.features.insn.API("ReadFile") in features
    assert capa.features.insn.API("CloseHandle") in features
    assert capa.features.insn.API("GetCurrentProcess") in features

    # spot-check: string arg from CreateFileW
    assert capa.features.common.String("secret.txt") in features

    # spot-check: numeric args
    assert capa.features.insn.Number(0x80000000) in features
    assert capa.features.insn.Number(512) in features
