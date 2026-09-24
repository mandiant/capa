#!/usr/bin/env python
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "protobuf",
#     "python-lancelot",
#     "rich",
# ]
# ///
#
# TODO:
#   - ignore stack cookie check
import sys
import json
import time
import logging
import argparse
import contextlib
from typing import Any
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass

import lancelot
import rich.padding
import lancelot.be2utils
import google.protobuf.message
from rich.text import Text
from rich.theme import Theme
from rich.markup import escape
from rich.console import Console
from lancelot.be2utils.binexport2_pb2 import BinExport2

logger = logging.getLogger("codemap")


@contextlib.contextmanager
def timing(msg: str):
    t0 = time.time()
    yield
    t1 = time.time()
    logger.debug("perf: %s: %0.2fs", msg, t1 - t0)


class Renderer:
    def __init__(self, console: Console):
        self.console: Console = console
        self.indent: int = 0

    @contextlib.contextmanager
    def indenting(self):
        self.indent += 1
        try:
            yield
        finally:
            self.indent -= 1

    @staticmethod
    def markup(s: str, **kwargs) -> Text:
        escaped_args = {k: (escape(v) if isinstance(v, str) else v) for k, v in kwargs.items()}
        return Text.from_markup(s.format(**escaped_args))

    def print(self, renderable, **kwargs):
        if not kwargs:
            return self.console.print(rich.padding.Padding(renderable, (0, 0, 0, self.indent * 2)))

        assert isinstance(renderable, str)
        return self.print(self.markup(renderable, **kwargs))

    def writeln(self, s: str):
        self.print(s)

    @contextlib.contextmanager
    def section(self, name):
        if isinstance(name, str):
            self.print("[title]{name}", name=name)
        elif isinstance(name, Text):
            name = name.copy()
            name.stylize_before(self.console.get_style("title"))
            self.print(name)
        else:
            raise ValueError("unexpected section name")

        with self.indenting():
            yield


@dataclass
class AssemblageLocation:
    name: str
    file: str
    prototype: str
    rva: int

    @property
    def path(self):
        if not self.file.endswith(")"):
            return self.file

        return self.file.rpartition(" (")[0]

    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        return cls(
            name=data["name"],
            file=data["file"],
            prototype=data["prototype"],
            rva=data["function_start"],
        )

    @staticmethod
    def from_json(doc: str):
        return AssemblageLocation.from_dict(json.loads(doc))


def main(argv: list[str] | None = None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Inspect BinExport2 files")
    parser.add_argument("input_file", type=Path, help="path to input file")
    parser.add_argument("--capa", type=Path, help="path to capa JSON results file")
    parser.add_argument("--assemblage", type=Path, help="path to Assemblage JSONL file")
    parser.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable all output but errors")
    args = parser.parse_args(args=argv)

    logging.basicConfig()
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    theme = Theme(
        {
            "decoration": "grey54",
            "title": "yellow",
            "key": "black",
            "value": "blue",
            "default": "black",
        },
        inherit=False,
    )
    console = Console(theme=theme, markup=False, emoji=False)
    o = Renderer(console)

    be2: BinExport2
    buf: bytes
    try:
        # easiest way to determine if this is a BinExport2 proto is...
        # to just try to decode it.
        buf = args.input_file.read_bytes()
        with timing("loading BinExport2"):
            be2 = BinExport2()
            be2.ParseFromString(buf)

    except google.protobuf.message.DecodeError:
        with timing("analyzing file"):
            input_file: Path = args.input_file
            buf = lancelot.get_binexport2_bytes_from_bytes(input_file.read_bytes())

        with timing("loading BinExport2"):
            be2 = BinExport2()
            be2.ParseFromString(buf)

    with timing("indexing BinExport2"):
        idx = lancelot.be2utils.BinExport2Index(be2)

    matches_by_function: defaultdict[int, set[str]] = defaultdict(set)
    if args.capa:
        with timing("loading capa"):
            doc = json.loads(args.capa.read_text())

            functions_by_basic_block: dict[int, int] = {}
            for function in doc["meta"]["analysis"]["layout"]["functions"]:
                for basic_block in function["matched_basic_blocks"]:
                    functions_by_basic_block[basic_block["address"]["value"]] = function["address"]["value"]

            matches_by_address: defaultdict[int, set[str]] = defaultdict(set)
            for rule_name, results in doc["rules"].items():
                for location, _ in results["matches"]:
                    if location["type"] != "absolute":
                        continue
                    address = location["value"]
                    matches_by_address[location["value"]].add(rule_name)

            for address, matches in matches_by_address.items():
                if function := functions_by_basic_block.get(address):
                    if function in idx.thunks:
                        # forward any capa for a thunk to its target
                        # since viv may not recognize the thunk as a separate function.
                        logger.debug("forwarding capa matches from thunk 0x%x to 0x%x", function, idx.thunks[function])
                        function = idx.thunks[function]

                    matches_by_function[function].update(matches)
                    for match in matches:
                        logger.info("capa: 0x%x: %s", function, match)
                else:
                    # we don't know which function this is.
                    # hopefully its a function recognized in our BinExport analysis.
                    # *shrug*
                    #
                    # apparently viv doesn't emit function entries for thunks?
                    # or somehow our layout is messed up.

                    if address in idx.thunks:
                        # forward any capa for a thunk to its target
                        # since viv may not recognize the thunk as a separate function.
                        logger.debug("forwarding capa matches from thunk 0x%x to 0x%x", address, idx.thunks[address])
                        address = idx.thunks[address]
                        # since we found the thunk, we know this is a BinExport-recognized function.
                        # so thats nice.
                        for match in matches:
                            logger.info("capa: 0x%x: %s", address, match)
                    else:
                        logger.warning("unknown address: 0x%x: %s", address, matches)

                    matches_by_function[address].update(matches)

    # guess the base address (which BinExport2) does not track explicitly,
    # by assuming it is the lowest mapped page.
    base_address = min(map(lambda section: section.address, be2.section))
    logging.info("guessed base address: 0x%x", base_address)

    assemblage_locations_by_va: dict[int, AssemblageLocation] = {}
    if args.assemblage:
        with timing("loading assemblage"):
            with args.assemblage.open("rt", encoding="utf-8") as f:
                for line in f:
                    if not line:
                        continue
                    location = AssemblageLocation.from_json(line)
                    assemblage_locations_by_va[base_address + location.rva] = location

    # update function names for the in-memory BinExport2 using Assemblage data.
    # this won't affect the be2 on disk, because we don't serialize it back out.
    for address, location in assemblage_locations_by_va.items():
        if not location.name:
            continue

        if vertex_index := idx.vertex_index_by_address.get(address):
            vertex = be2.call_graph.vertex[vertex_index].demangled_name = location.name

    # index all the callers of each function, resolving thunks.
    # idx.callers_by_vertex_id does not resolve thunks.
    resolved_callers_by_vertex_id = defaultdict(set)
    for edge in be2.call_graph.edge:
        source_index = edge.source_vertex_index

        if lancelot.be2utils.is_thunk_vertex(be2.call_graph.vertex[source_index]):
            # we don't care about the callers that are thunks.
            continue

        if lancelot.be2utils.is_thunk_vertex(be2.call_graph.vertex[edge.target_vertex_index]):
            thunk_vertex = be2.call_graph.vertex[edge.target_vertex_index]
            thunk_address = thunk_vertex.address

            target_address = idx.thunks[thunk_address]
            target_index = idx.vertex_index_by_address[target_address]
            logger.debug(
                "call %s -(thunk)-> %s",
                idx.get_function_name_by_vertex(source_index),
                idx.get_function_name_by_vertex(target_index),
            )
        else:
            target_index = edge.target_vertex_index
            logger.debug(
                "call %s -> %s",
                idx.get_function_name_by_vertex(source_index),
                idx.get_function_name_by_vertex(target_index),
            )
        resolved_callers_by_vertex_id[target_index].add(source_index)

    t0 = time.time()

    with o.section("meta"):
        o.writeln(f"name:   {be2.meta_information.executable_name}")
        o.writeln(f"sha256: {be2.meta_information.executable_id}")
        o.writeln(f"arch:   {be2.meta_information.architecture_name}")
        o.writeln(f"ts:     {be2.meta_information.timestamp}")

    with o.section("modules"):
        for module in be2.module:
            o.writeln(f"- {module.name}")
        if not be2.module:
            o.writeln("(none)")

    with o.section("sections"):
        for section in be2.section:
            perms = ""
            perms += "r" if section.flag_r else "-"
            perms += "w" if section.flag_w else "-"
            perms += "x" if section.flag_x else "-"
            o.writeln(f"- {hex(section.address)} {perms} {hex(section.size)}")

    with o.section("libraries"):
        for library in be2.library:
            o.writeln(
                f"- {library.name:<12s} {'(static)' if library.is_static else ''}{(' at ' + hex(library.load_address)) if library.HasField('load_address') else ''}"
            )
        if not be2.library:
            o.writeln("(none)")

    vertex_order_by_address = {address: i for (i, address) in enumerate(idx.vertex_index_by_address.keys())}

    with o.section("functions"):
        last_address = None
        for _, vertex_index in idx.vertex_index_by_address.items():
            vertex = be2.call_graph.vertex[vertex_index]
            vertex_order = vertex_order_by_address[vertex.address]

            if vertex.HasField("library_index"):
                continue

            if vertex.HasField("module_index"):
                continue

            function_name = idx.get_function_name_by_vertex(vertex_index)

            if last_address:
                try:
                    last_path = assemblage_locations_by_va[last_address].path
                    path = assemblage_locations_by_va[vertex.address].path
                    if last_path != path:
                        o.print(o.markup("[blue]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~[/] [title]file[/] {path}\n", path=path))
                except KeyError:
                    pass
            last_address = vertex.address

            if lancelot.be2utils.is_thunk_vertex(vertex):
                with o.section(
                    o.markup(
                        "thunk [default]{function_name}[/] [decoration]@ {function_address}[/]",
                        function_name=function_name,
                        function_address=hex(vertex.address),
                    )
                ):
                    continue

            with o.section(
                o.markup(
                    "function [default]{function_name}[/] [decoration]@ {function_address}[/]",
                    function_name=function_name,
                    function_address=hex(vertex.address),
                )
            ):
                if vertex.address in idx.thunks:
                    o.writeln("")
                    continue

                # keep the xrefs separate from the calls, since they're visually hard to distinguish.
                # use local index of callers that has resolved intermediate thunks,
                # since they are sometimes stored in a physically distant location.
                for caller_index in resolved_callers_by_vertex_id.get(vertex_index, []):
                    caller_vertex = be2.call_graph.vertex[caller_index]
                    caller_order = vertex_order_by_address[caller_vertex.address]
                    caller_delta = caller_order - vertex_order
                    if caller_delta < 0:
                        direction = "↑"
                    else:
                        direction = "↓"

                    o.print(
                        "xref:    [decoration]{direction}[/] {name} [decoration]({delta:+})[/]",
                        direction=direction,
                        name=idx.get_function_name_by_vertex(caller_index),
                        delta=caller_delta,
                    )

                if vertex.address not in idx.flow_graph_index_by_address:
                    num_basic_blocks = 0
                    num_instructions = 0
                    num_edges = 0
                    total_instruction_size = 0
                else:
                    flow_graph_index = idx.flow_graph_index_by_address[vertex.address]
                    flow_graph = be2.flow_graph[flow_graph_index]
                    num_basic_blocks = len(flow_graph.basic_block_index)
                    num_instructions = sum(
                        len(list(idx.instruction_indices(be2.basic_block[bb_idx])))
                        for bb_idx in flow_graph.basic_block_index
                    )
                    num_edges = len(flow_graph.edge)
                    total_instruction_size = 0
                    for bb_idx in flow_graph.basic_block_index:
                        basic_block = be2.basic_block[bb_idx]
                        for _, instruction, _ in idx.basic_block_instructions(basic_block):
                            total_instruction_size += len(instruction.raw_bytes)

                o.writeln(
                    f"B/E/I:     {num_basic_blocks} / {num_edges} / {num_instructions} ({total_instruction_size} bytes)"
                )

                for match in matches_by_function.get(vertex.address, []):
                    o.writeln(f"capa:      {match}")

                if vertex.address in idx.flow_graph_index_by_address:
                    flow_graph_index = idx.flow_graph_index_by_address[vertex.address]
                    flow_graph = be2.flow_graph[flow_graph_index]

                    seen_callees = set()

                    for basic_block_index in flow_graph.basic_block_index:
                        basic_block = be2.basic_block[basic_block_index]

                        for instruction_index, instruction, _ in idx.basic_block_instructions(basic_block):
                            if instruction.call_target:
                                for call_target_address in instruction.call_target:
                                    if call_target_address in idx.thunks:
                                        call_target_address = idx.thunks[call_target_address]

                                    call_target_index = idx.vertex_index_by_address[call_target_address]
                                    call_target_vertex = be2.call_graph.vertex[call_target_index]

                                    if call_target_vertex.HasField("library_index"):
                                        continue

                                    if call_target_vertex.address in seen_callees:
                                        continue
                                    seen_callees.add(call_target_vertex.address)

                                    call_target_order = vertex_order_by_address[call_target_address]
                                    call_target_delta = call_target_order - vertex_order
                                    call_target_name = idx.get_function_name_by_address(call_target_address)
                                    if call_target_delta < 0:
                                        direction = "↑"
                                    else:
                                        direction = "↓"

                                    o.print(
                                        "calls:   [decoration]{direction}[/] {name} [decoration]({delta:+})[/]",
                                        direction=direction,
                                        name=call_target_name,
                                        delta=call_target_delta,
                                    )

                    for basic_block_index in flow_graph.basic_block_index:
                        basic_block = be2.basic_block[basic_block_index]

                        for instruction_index, instruction, _ in idx.basic_block_instructions(basic_block):
                            if instruction.call_target:
                                for call_target_address in instruction.call_target:
                                    call_target_index = idx.vertex_index_by_address[call_target_address]
                                    call_target_vertex = be2.call_graph.vertex[call_target_index]

                                    if not call_target_vertex.HasField("library_index"):
                                        continue

                                    if call_target_vertex.address in seen_callees:
                                        continue
                                    seen_callees.add(call_target_vertex.address)

                                    call_target_name = idx.get_function_name_by_address(call_target_address)
                                    o.print(
                                        "api:       {name}",
                                        name=call_target_name,
                                    )

                    seen_strings = set()
                    for basic_block_index in flow_graph.basic_block_index:
                        basic_block = be2.basic_block[basic_block_index]

                        for instruction_index, instruction, _ in idx.basic_block_instructions(basic_block):
                            if instruction_index in idx.string_reference_index_by_source_instruction_index:
                                for string_reference_index in idx.string_reference_index_by_source_instruction_index[
                                    instruction_index
                                ]:
                                    string_reference = be2.string_reference[string_reference_index]
                                    string_index = string_reference.string_table_index
                                    string = be2.string_table[string_index]

                                    if string in seen_strings:
                                        continue
                                    seen_strings.add(string)

                                    o.print(
                                        'string:   [decoration]"[/]{string}[decoration]"[/]',
                                        string=string.rstrip(),
                                    )

                o.print("")

    t1 = time.time()
    logger.debug("perf: rendering BinExport2: %0.2fs", t1 - t0)


if __name__ == "__main__":
    sys.exit(main())
