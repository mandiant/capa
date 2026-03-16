from __future__ import annotations

import json
import logging
import sys
import time
import argparse
from pathlib import Path
from collections import defaultdict

from rich.theme import Theme
from rich.console import Console
from rich.logging import RichHandler

from mapa.model import AssemblageLocation

logger = logging.getLogger("mapa")


def _load_capa_matches(
    capa_path: Path,
    thunk_targets: dict[int, int],
    get_containing_function: object,
) -> dict[int, set[str]]:
    """Load capa JSON and map matches to function addresses.

    get_containing_function should be a callable(address) -> int|None
    that returns the function start address for a given address.
    """
    doc = json.loads(capa_path.read_text())

    functions_by_basic_block: dict[int, int] = {}
    for function in doc["meta"]["analysis"]["layout"]["functions"]:
        for basic_block in function["matched_basic_blocks"]:
            functions_by_basic_block[basic_block["address"]["value"]] = function["address"]["value"]

    matches_by_address: defaultdict[int, set[str]] = defaultdict(set)
    for rule_name, results in doc["rules"].items():
        for location, _ in results["matches"]:
            if location["type"] != "absolute":
                continue
            matches_by_address[location["value"]].add(rule_name)

    matches_by_function: defaultdict[int, set[str]] = defaultdict(set)
    for address, matches in matches_by_address.items():
        func_addr = functions_by_basic_block.get(address, address)

        if func_addr in thunk_targets:
            logger.debug("forwarding capa matches from thunk 0x%x to 0x%x", func_addr, thunk_targets[func_addr])
            func_addr = thunk_targets[func_addr]

        matches_by_function[func_addr].update(matches)
        for match in matches:
            logger.info("capa: 0x%x: %s", func_addr, match)

    return dict(matches_by_function)


def _load_assemblage(assemblage_path: Path, base_address: int) -> dict[int, AssemblageLocation]:
    locations: dict[int, AssemblageLocation] = {}
    with assemblage_path.open("rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            location = AssemblageLocation.from_json(line)
            locations[base_address + location.rva] = location
    return locations


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="MAPA: binary function map")
    parser.add_argument("input_file", type=Path, help="path to input file (binary, .i64, or .idb)")
    parser.add_argument("--capa", type=Path, help="path to capa JSON results file")
    parser.add_argument("--assemblage", type=Path, help="path to Assemblage JSONL file")
    parser.add_argument("--verbose", action="store_true", help="enable verbose logging")
    parser.add_argument("--quiet", action="store_true", help="disable all output but errors")
    args = parser.parse_args(args=argv)

    stderr_console = Console(stderr=True)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO),
        format="%(message)s",
        handlers=[RichHandler(console=stderr_console, show_path=False, rich_tracebacks=args.verbose)],
    )

    from mapa.ida_db import resolve_database, open_database_session
    from mapa.collector import collect_report
    from mapa.renderer import render_report

    t0 = time.time()
    db_path, md5, sha256 = resolve_database(args.input_file)
    logger.debug("perf: resolve_database: %0.2fs", time.time() - t0)

    theme = Theme(
        {
            "decoration": "grey54",
            "title": "yellow",
            "key": "blue",
            "value": "blue",
            "default": "blue",
        },
        inherit=False,
    )
    console = Console(theme=theme, markup=False, emoji=False)

    t0 = time.time()
    with open_database_session(db_path) as db:
        logger.debug("perf: open_database: %0.2fs", time.time() - t0)

        base_address = db.base_address or 0

        assemblage_locations: dict[int, AssemblageLocation] = {}
        if args.assemblage:
            assemblage_locations = _load_assemblage(args.assemblage, base_address)

        # We need thunk targets for capa match forwarding.
        # The collector will compute them too, but we need them before collection
        # for capa loading. We'll pass capa matches into the collector.
        matches_by_function: dict[int, set[str]] = {}
        if args.capa:
            # For now, pass an empty thunk_targets; capa matches that land
            # on thunks will be forwarded during collection.
            # The collector handles thunk forwarding internally via
            # resolve_thunk_target, which the capa loader needs too.
            # To avoid duplicating thunk logic, we do a simple pass here
            # and let the collector handle the rest.
            from mapa.collector import _resolve_thunk_target, _build_import_index, _build_extern_index
            from ida_domain.functions import FunctionFlags

            import_index = _build_import_index(db)
            extern_addrs = _build_extern_index(db)

            thunk_targets: dict[int, int] = {}
            for func in db.functions:
                flags = db.functions.get_flags(func)
                if flags and FunctionFlags.THUNK in flags:
                    target = _resolve_thunk_target(db, int(func.start_ea), import_index, extern_addrs)
                    if target is not None:
                        thunk_targets[int(func.start_ea)] = target

            matches_by_function = _load_capa_matches(
                args.capa,
                thunk_targets,
                lambda addr: None,
            )

        t0 = time.time()
        report = collect_report(
            db,
            md5=md5,
            sha256=sha256,
            matches_by_function=matches_by_function,
            assemblage_locations=assemblage_locations,
        )
        logger.debug("perf: collect_report: %0.2fs", time.time() - t0)

    t0 = time.time()
    render_report(report, console)
    logger.debug("perf: render_report: %0.2fs", time.time() - t0)

    return 0


if __name__ == "__main__":
    sys.exit(main())
