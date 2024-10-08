import sys
import logging
from typing import Any, Literal, Optional
from pathlib import Path

from pydantic import BeforeValidator
from typing_extensions import Annotated
from pydantic.dataclasses import dataclass

HexInt = Annotated[int, BeforeValidator(lambda v: int(v.strip('"'), 0x10))]
QuotedInt = Annotated[int, BeforeValidator(lambda v: int(v.strip('"')))]
QuotedString = Annotated[str, BeforeValidator(lambda v: v.strip('"'))]


logger = logging.getLogger("vmray.flog")


@dataclass
class Region:
    id: QuotedInt
    start_va: HexInt
    end_va: HexInt
    monitored: bool
    entry_point: HexInt
    region_type: Literal["private"] | Literal["mapped_file"] | Literal["pagefile_backed"]
    name: QuotedString
    filename: str


@dataclass
class Event:
    timestamp: tuple[int, int]
    api: str
    args: str
    rv: Optional[int]


@dataclass
class Thread:
    id: QuotedInt
    os_tid: HexInt
    events: list[Event]


@dataclass
class Process:
    id: QuotedInt
    image_name: QuotedString
    filename: QuotedString
    page_root: HexInt
    os_pid: HexInt
    os_integrity_level: HexInt
    os_privileges: HexInt
    monitor_reason: Literal['"analysis_target"'] | Literal['"rpc_server"']
    parent_id: HexInt
    os_parent_pid: HexInt
    cmd_line: str  # TODO: json decode str
    cur_dir: str  # TODO: json decode str
    os_username: str  # TODO: json decode str
    bitness: QuotedInt  # TODO: enum 32 or 64
    os_groups: str  # TODO: list of str
    regions: list[Region]
    threads: list[Thread]


@dataclass
class Flog:
    processes: list[Process]

    processes_by_id: dict[int, Process]
    regions_by_id: dict[int, Region]
    threads_by_id: dict[int, Thread]


def parse_properties(txt: str) -> dict[str, Any]:
    properties = {}
    for line in txt.partition("\n\n")[0].splitlines():
        key, _, value = line.lstrip().partition(" = ")
        properties[key] = value

    return properties


def parse_region(txt: str) -> Region:
    # like:
    #
    #    Region:
    # 	              id = 125
    # 	        start_va = 0x10000
    # 	          end_va = 0x2ffff
    # 	       monitored = 1
    # 	     entry_point = 0x0
    # 	     region_type = private
    # 	            name = "private_0x0000000000010000"
    # 	        filename = ""
    region_kwargs = parse_properties(txt)
    return Region(**region_kwargs)


def parse_event(line: str) -> Event:
    # like:
    #
    #    	[0066.433] CoInitializeEx (pvReserved=0x0, dwCoInit=0x2) returned 0x0
    #    	[0071.184] RegisterClipboardFormatW (lpszFormat="WM_GETCONTROLTYPE") returned 0xc1dc
    #    	[0072.750] GetCurrentProcess () returned 0xffffffffffffffff
    numbers, _, rest = line.lstrip()[1:].partition("] ")
    major, _, minor = numbers.partition(".")
    majori = int(major.lstrip("0") or "0")
    minori = int(minor.lstrip("0") or "0")
    timestamp = (majori, minori)

    api, _, rest = rest.partition(" (")
    args, _, rest = rest.rpartition(")")

    if " returned " in rest:
        _, _, rvs = rest.partition(" returned ")
        rv = int(rvs, 0x10)
    else:
        rv = None

    return Event(
        timestamp=timestamp,
        api=api,
        args=args,
        rv=rv,
    )


def parse_thread(txt: str) -> Thread:
    # like:
    #
    #    Thread:
    #    	id = 1
    #    	os_tid = 0x117c
    #
    #    	[0066.433] CoInitializeEx (pvReserved=0x0, dwCoInit=0x2) returned 0x0
    #    	[0071.184] RegisterClipboardFormatW (lpszFormat="WM_GETCONTROLTYPE") returned 0xc1dc
    #    	[0072.750] GetCurrentProcess () returned 0xffffffffffffffff
    thread_kwargs = parse_properties(txt)

    events = []
    for line in txt.splitlines():
        if not line.startswith("\t["):
            continue

        events.append(parse_event(line))

    return Thread(
        events=events,
        **thread_kwargs,
    )


def parse_process(txt: str) -> Process:
    # properties look like:
    #
    #    id = "1"
    #    image_name = "svchost.exe"
    #    filename = "c:\\users\\rdhj0cnfevzx\\desktop\\svchost.exe"
    #    page_root = "0x751fc000"
    #    os_pid = "0x118c"
    #    os_integrity_level = "0x3000"
    #    os_privileges = "0x60800000"
    #    monitor_reason = "analysis_target"
    #    parent_id = "0"
    #    os_parent_pid = "0x7d8"
    #    cmd_line = "\"c:\\users\\rdhj0cnfevzx\\desktop\\svchost.exe\" "
    #    cur_dir = "c:\\users\\rdhj0cnfevzx\\desktop\\"
    #    os_username = "xc64zb\\rdhj0cnfevzx"
    #    bitness = "32"
    #    os_groups = "xc64zb\\domain users" [0x7], "everyone" [0x7], ...
    process_kwargs = parse_properties(txt)

    regions = []
    for region in txt.split("\nRegion:\n")[1:]:
        regions.append(parse_region(region))

    threads = []
    for thread in txt.split("\nThread:\n")[1:]:
        threads.append(parse_thread(thread))

    return Process(
        regions=regions,
        threads=threads,
        **process_kwargs,
    )


def parse_processes(txt: str) -> list[Process]:
    processes = []
    for process in txt.split("\nProcess:\n")[1:]:
        processes.append(parse_process(process))
    return processes


def parse_flog(txt: str) -> Flog:
    # the header probably fits within this size
    header_lines = txt[:512].splitlines()

    # file may start with: | ef bb bf |
    assert "# Flog Txt Version 1" in header_lines[0]

    for line in header_lines[1:]:
        line = line.strip()
        if not line.startswith("#"):
            break

        # metadata lines, like:
        #
        #     Flog Txt Version 1
        #     Analyzer Version: 2024.4.1
        #     Analyzer Build Date: Sep  2 2024 06:30:10
        #     Log Creation Date: 08.10.2024 18:12:03.945c
        logger.debug("%s", line)

    processes = parse_processes(txt)
    processes_by_id = {process.id: process for process in processes}
    regions_by_id = {region.id: region for process in processes for region in process.regions}
    threads_by_id = {thread.id: thread for process in processes for thread in process.threads}

    return Flog(
        processes=processes,
        processes_by_id=processes_by_id,
        regions_by_id=regions_by_id,
        threads_by_id=threads_by_id,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    flog_path = Path(sys.argv[1])
    flog = parse_flog(flog_path.read_text(encoding="utf-8"))

    for process in flog.processes:
        print(f"{process.id=} {len(process.regions)=} {len(process.threads)=}")

        for region in process.regions:
            print(f"  {region.id=} {region.name}")

        for thread in process.threads:
            print(f"  {thread.id=} {len(thread.events)=}")


def test_event_timestamp():
    event = parse_event("	[0072.750] GetCurrentProcess () returned 0xffffffffffffffff")
    assert event.timestamp == (72, 750)


def test_event_api():
    event = parse_event("	[0072.750] GetCurrentProcess () returned 0xffffffffffffffff")
    assert event.api == "GetCurrentProcess"


def test_event_empty_args():
    event = parse_event("	[0072.750] GetCurrentProcess () returned 0xffffffffffffffff")
    assert len(event.args) == 0


# single arg
#	[0074.875] GetSystemMetrics (nIndex=75) returned 1

# no return value
#	[0083.567] CoTaskMemFree (pv=0x746aa0) 

# two args
#	[0085.491] GetWindowLongPtrW (hWnd=0x401f0, nIndex=-16) returned 0x6c10000

# in/out
#	[0086.848] GetClientRect (in: hWnd=0x401f0, lpRect=0x14d0c0 | out: lpRect=0x14d0c0) returned 1

# string
#	[0102.753] FindAtomW (lpString="GDI+Atom_4492_1") returned 0xc000

# int (hex)
#	[0102.756] GdipDeleteFont (font=0x1c504e00) returned 0x0

# int (decimal)
#	[0074.875] GetSystemMetrics (nIndex=75) returned 1

# int (negative)
#	[0085.491] GetWindowLongPtrW (hWnd=0x401f0, nIndex=-16) returned 0x6c10000

# struct
#	[0067.024] GetVersionExW (in: lpVersionInformation=0x14e3f0*(dwOSVersionInfoSize=0x114, dwMajorVersion=0x0, dwMinorVersion=0x0, dwBuildNumber=0x0, dwPlatformId=0x0, szCSDVersion="") | out: lpVersionInformation=0x14e3f0*(dwOSVersionInfoSize=0x114, dwMajorVersion=0x6, dwMinorVersion=0x2, dwBuildNumber=0x23f0, dwPlatformId=0x2, szCSDVersion="")) returned 1

# nested struct
#	[0111.527] CoCreateGuid (in: pguid=0x14c910 | out: pguid=0x14c910*(Data1=0x63ac5b46, Data2=0xc417, Data3=0x49b0, Data4=([0]=0xac, [1]=0xbf, [2]=0xb8, [3]=0xf3, [4]=0x8b, [5]=0x1a, [6]=0x51, [7]=0x78))) returned 0x0

# bytes
#	[0111.527] CoCreateGuid (in: pguid=0x14c910 | out: pguid=0x14c910*(Data1=0x63ac5b46, Data2=0xc417, Data3=0x49b0, Data4=([0]=0xac, [1]=0xbf, [2]=0xb8, [3]=0xf3, [4]=0x8b, [5]=0x1a, [6]=0x51, [7]=0x78))) returned 0x0
