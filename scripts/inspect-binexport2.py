#!/usr/bin/env python
"""
Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import io
import sys
import time
import logging
import argparse
import contextlib
from typing import Dict, List, Optional

import capa.main
import capa.features.extractors.binexport2
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger("inspect-binexport2")


@contextlib.contextmanager
def timing(msg: str):
    t0 = time.time()
    yield
    t1 = time.time()
    logger.debug("perf: %s: %0.2fs", msg, t1 - t0)


class Renderer:
    def __init__(self, o: io.StringIO):
        self.o = o
        self.indent = 0

    @contextlib.contextmanager
    def indenting(self):
        self.indent += 1
        try:
            yield
        finally:
            self.indent -= 1

    def write(self, s):
        self.o.write(s)

    def writeln(self, s):
        self.o.write("  " * self.indent)
        self.o.write(s)
        self.o.write("\n")

    @contextlib.contextmanager
    def section(self, name):
        self.writeln(name)
        with self.indenting():
            try:
                yield
            finally:
                pass
        self.writeln("/" + name)
        self.writeln("")

    def getvalue(self):
        return self.o.getvalue()


# internal to `render_operand`
def _render_expression_tree(
    be2: BinExport2,
    operand: BinExport2.Operand,
    expression_tree: List[List[int]],
    tree_index: int,
    o: io.StringIO,
):

    expression_index = operand.expression_index[tree_index]
    expression = be2.expression[expression_index]
    children_tree_indexes: List[int] = expression_tree[tree_index]

    if expression.type == BinExport2.Expression.REGISTER:
        o.write(expression.symbol)
        assert len(children_tree_indexes) == 0
        return

    elif expression.type == BinExport2.Expression.SYMBOL:
        o.write(expression.symbol)
        assert len(children_tree_indexes) <= 1

        if len(children_tree_indexes) == 0:
            return
        elif len(children_tree_indexes) == 1:
            # like: v
            # from: mov v0.D[0x1], x9
            #           |
            #           0
            #           .
            #           |
            #           D
            child_index = children_tree_indexes[0]
            _render_expression_tree(be2, operand, expression_tree, child_index, o)
            return
        else:
            raise NotImplementedError(len(children_tree_indexes))

    elif expression.type == BinExport2.Expression.IMMEDIATE_INT:
        o.write(f"0x{expression.immediate:X}")
        assert len(children_tree_indexes) == 0
        return

    elif expression.type == BinExport2.Expression.SIZE_PREFIX:
        # like: b4
        #
        # We might want to use this occasionally, such as to disambiguate the
        # size of MOVs into/out of memory. But I'm not sure when/where we need that yet.
        #
        # IDA spams this size prefix hint *everywhere*, so we can't rely on the exporter
        # to provide it only when necessary.
        assert len(children_tree_indexes) == 1
        child_index = children_tree_indexes[0]
        _render_expression_tree(be2, operand, expression_tree, child_index, o)
        return

    elif expression.type == BinExport2.Expression.OPERATOR:

        if len(children_tree_indexes) == 1:
            # prefix operator, like "ds:"
            if expression.symbol != "!":
                o.write(expression.symbol)

            child_index = children_tree_indexes[0]
            _render_expression_tree(be2, operand, expression_tree, child_index, o)

            # postfix operator, like "!" in aarch operand "[x1, 8]!"
            if expression.symbol == "!":
                o.write(expression.symbol)
            return

        elif len(children_tree_indexes) == 2:
            # infix operator: like "+" in "ebp+10"
            child_a = children_tree_indexes[0]
            child_b = children_tree_indexes[1]
            _render_expression_tree(be2, operand, expression_tree, child_a, o)
            o.write(expression.symbol)
            _render_expression_tree(be2, operand, expression_tree, child_b, o)
            return

        elif len(children_tree_indexes) == 3:
            # infix operator: like "+" in "ebp+ecx+10"
            child_a = children_tree_indexes[0]
            child_b = children_tree_indexes[1]
            child_c = children_tree_indexes[2]
            _render_expression_tree(be2, operand, expression_tree, child_a, o)
            o.write(expression.symbol)
            _render_expression_tree(be2, operand, expression_tree, child_b, o)
            o.write(expression.symbol)
            _render_expression_tree(be2, operand, expression_tree, child_c, o)
            return

        else:
            raise NotImplementedError(len(children_tree_indexes))

    elif expression.type == BinExport2.Expression.DEREFERENCE:
        o.write("[")
        assert len(children_tree_indexes) == 1
        child_index = children_tree_indexes[0]
        _render_expression_tree(be2, operand, expression_tree, child_index, o)
        o.write("]")
        return

    elif expression.type == BinExport2.Expression.IMMEDIATE_FLOAT:
        raise NotImplementedError(expression.type)

    else:
        raise NotImplementedError(expression.type)


_OPERAND_CACHE: Dict[int, str] = {}


def render_operand(be2: BinExport2, operand: BinExport2.Operand, index: Optional[int] = None) -> str:
    # For the mimikatz example file, there are 138k distinct operands.
    # Of those, only 11k are unique, which is less than 10% of the total.
    # The most common operands are seen 37k, 24k, 17k, 15k, 11k, ... times.
    # In other words, the most common five operands account for 100k instances,
    # which is around 75% of operand instances.
    # Therefore, we expect caching to be fruitful, trading memory for CPU time.
    #
    # No caching:   6.045 s ± 0.164 s   [User: 5.916 s, System: 0.129 s]
    # With caching: 4.259 s ± 0.161 s   [User: 4.141 s, System: 0.117 s]
    #
    # So we can save 30% of CPU time by caching operand rendering.
    #
    # Other measurements:
    #
    # perf: loading BinExport2:   0.06s
    # perf: indexing BinExport2:  0.34s
    # perf: rendering BinExport2: 1.96s
    # perf: writing BinExport2:   1.13s
    # ________________________________________________________
    # Executed in    4.40 secs    fish           external
    #    usr time    4.22 secs    0.00 micros    4.22 secs
    #    sys time    0.18 secs  842.00 micros    0.18 secs
    if index and index in _OPERAND_CACHE:
        return _OPERAND_CACHE[index]

    o = io.StringIO()
    tree = capa.features.extractors.binexport2.helpers._build_expression_tree(be2, operand)
    _render_expression_tree(be2, operand, tree, 0, o)
    s = o.getvalue()

    if index:
        _OPERAND_CACHE[index] = s

    return s


def inspect_operand(be2: BinExport2, operand: BinExport2.Operand):
    expression_tree = capa.features.extractors.binexport2.helpers._build_expression_tree(be2, operand)

    def rec(tree_index, indent=0):
        expression_index = operand.expression_index[tree_index]
        expression = be2.expression[expression_index]
        children_tree_indexes: List[int] = expression_tree[tree_index]

        NEWLINE = "\n"
        print(f"    {'  ' * indent}expression: {str(expression).replace(NEWLINE, ', ')}")
        for child_index in children_tree_indexes:
            rec(child_index, indent + 1)

    rec(0)


def inspect_instruction(be2: BinExport2, instruction: BinExport2.Instruction, address: int):
    mnemonic = be2.mnemonic[instruction.mnemonic_index]
    print("instruction:")
    print(f"  address: {hex(address)}")
    print(f"  mnemonic: {mnemonic.name}")

    print("  operands:")
    for i, operand_index in enumerate(instruction.operand_index):
        print(f"  - operand {i}: [{operand_index}]")
        operand = be2.operand[operand_index]
        # Ghidra bug where empty operands (no expressions) may
        # exist so we skip those for now (see https://github.com/NationalSecurityAgency/ghidra/issues/6817)
        if len(operand.expression_index) > 0:
            inspect_operand(be2, operand)


def main(argv=None):

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Inspect BinExport2 files")
    capa.main.install_common_args(parser, wanted={"input_file"})
    parser.add_argument("--instruction", type=lambda v: int(v, 0))
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    o = Renderer(io.StringIO())
    with timing("loading BinExport2"):
        be2: BinExport2 = capa.features.extractors.binexport2.get_binexport2(args.input_file)

    with timing("indexing BinExport2"):
        idx = capa.features.extractors.binexport2.BinExport2Index(be2)

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

    with o.section("functions"):
        for vertex_index, vertex in enumerate(be2.call_graph.vertex):
            if not vertex.HasField("address"):
                continue

            with o.section(f"function {idx.get_function_name_by_vertex(vertex_index)} @ {hex(vertex.address)}"):
                o.writeln(f"type:      {vertex.Type.Name(vertex.type)}")

                if vertex.HasField("mangled_name"):
                    o.writeln(f"name:      {vertex.mangled_name}")

                if vertex.HasField("demangled_name"):
                    o.writeln(f"demangled: {vertex.demangled_name}")

                if vertex.HasField("library_index"):
                    # TODO(williballenthin): this seems to be incorrect for Ghidra exporter
                    # https://github.com/mandiant/capa/issues/1755
                    library = be2.library[vertex.library_index]
                    o.writeln(f"library:   [{vertex.library_index}] {library.name}")

                if vertex.HasField("module_index"):
                    module = be2.module[vertex.module_index]
                    o.writeln(f"module:    [{vertex.module_index}] {module.name}")

                if idx.callees_by_vertex_index[vertex_index] or idx.callers_by_vertex_index[vertex_index]:
                    o.writeln("xrefs:")

                    for caller_index in idx.callers_by_vertex_index[vertex_index]:
                        o.writeln(f"  ← {idx.get_function_name_by_vertex(caller_index)}")

                    for callee_index in idx.callees_by_vertex_index[vertex_index]:
                        o.writeln(f"  → {idx.get_function_name_by_vertex(callee_index)}")

                if vertex.address not in idx.flow_graph_index_by_address:
                    o.writeln("(no flow graph)")
                else:
                    flow_graph_index = idx.flow_graph_index_by_address[vertex.address]
                    flow_graph = be2.flow_graph[flow_graph_index]

                    o.writeln("")
                    for basic_block_index in flow_graph.basic_block_index:
                        basic_block = be2.basic_block[basic_block_index]
                        basic_block_address = idx.get_basic_block_address(basic_block_index)

                        with o.section(f"basic block {hex(basic_block_address)}"):
                            for edge in idx.target_edges_by_basic_block_index[basic_block_index]:
                                if edge.type == BinExport2.FlowGraph.Edge.Type.CONDITION_FALSE:
                                    continue

                                source_basic_block_index = edge.source_basic_block_index
                                source_basic_block_address = idx.get_basic_block_address(source_basic_block_index)

                                o.writeln(
                                    f"↓ {BinExport2.FlowGraph.Edge.Type.Name(edge.type)} basic block {hex(source_basic_block_address)}"
                                )

                            for instruction_index, instruction, instruction_address in idx.basic_block_instructions(
                                basic_block
                            ):
                                mnemonic = be2.mnemonic[instruction.mnemonic_index]

                                operands = []
                                for operand_index in instruction.operand_index:
                                    operand = be2.operand[operand_index]
                                    # Ghidra bug where empty operands (no expressions) may
                                    # exist so we skip those for now (see https://github.com/NationalSecurityAgency/ghidra/issues/6817)
                                    if len(operand.expression_index) > 0:
                                        operands.append(render_operand(be2, operand, index=operand_index))

                                call_targets = ""
                                if instruction.call_target:
                                    call_targets = " "
                                    for call_target_address in instruction.call_target:
                                        call_target_name = idx.get_function_name_by_address(call_target_address)
                                        call_targets += f"→ function {call_target_name} @ {hex(call_target_address)} "

                                data_references = ""
                                if instruction_index in idx.data_reference_index_by_source_instruction_index:
                                    data_references = " "
                                    for data_reference_index in idx.data_reference_index_by_source_instruction_index[
                                        instruction_index
                                    ]:
                                        data_reference = be2.data_reference[data_reference_index]
                                        data_reference_address = data_reference.address
                                        data_references += f"⇥ data {hex(data_reference_address)} "

                                string_references = ""
                                if instruction_index in idx.string_reference_index_by_source_instruction_index:
                                    string_references = " "
                                    for (
                                        string_reference_index
                                    ) in idx.string_reference_index_by_source_instruction_index[instruction_index]:
                                        string_reference = be2.string_reference[string_reference_index]
                                        string_index = string_reference.string_table_index
                                        string = be2.string_table[string_index]
                                        string_references += f'⇥ string "{string.rstrip()}" '

                                comments = ""
                                if instruction.comment_index:
                                    comments = " "
                                    for comment_index in instruction.comment_index:
                                        comment = be2.comment[comment_index]
                                        comment_string = be2.string_table[comment.string_table_index]
                                        comments += f"; {BinExport2.Comment.Type.Name(comment.type)} {comment_string} "

                                o.writeln(
                                    f"{hex(instruction_address)}  {mnemonic.name:<12s}{', '.join(operands):<14s}{call_targets}{data_references}{string_references}{comments}"
                                )

                            does_fallthrough = False
                            for edge in idx.source_edges_by_basic_block_index[basic_block_index]:
                                if edge.type == BinExport2.FlowGraph.Edge.Type.CONDITION_FALSE:
                                    does_fallthrough = True
                                    continue

                                back_edge = ""
                                if edge.HasField("is_back_edge") and edge.is_back_edge:
                                    back_edge = "↑"

                                target_basic_block_index = edge.target_basic_block_index
                                target_basic_block_address = idx.get_basic_block_address(target_basic_block_index)
                                o.writeln(
                                    f"→ {BinExport2.FlowGraph.Edge.Type.Name(edge.type)} basic block {hex(target_basic_block_address)} {back_edge}"
                                )

                            if does_fallthrough:
                                o.writeln("↓ CONDITION_FALSE")

    with o.section("data"):
        for data_address in sorted(idx.data_reference_index_by_target_address.keys()):
            if data_address in idx.insn_address_by_index:
                # appears to be code
                continue

            data_xrefs: List[int] = []
            for data_reference_index in idx.data_reference_index_by_target_address[data_address]:
                data_reference = be2.data_reference[data_reference_index]
                instruction_address = idx.get_insn_address(data_reference.instruction_index)
                data_xrefs.append(instruction_address)

            if not data_xrefs:
                continue

            o.writeln(f"{hex(data_address)} ⇤ {hex(data_xrefs[0])}")
            for data_xref in data_xrefs[1:]:
                o.writeln(f"{' ' * len(hex(data_address))} ↖ {hex(data_xref)}")

    t1 = time.time()
    logger.debug("perf: rendering BinExport2: %0.2fs", t1 - t0)

    with timing("writing to STDOUT"):
        print(o.getvalue())

    if args.instruction:
        insn = idx.insn_by_address[args.instruction]
        inspect_instruction(be2, insn, args.instruction)


if __name__ == "__main__":
    sys.exit(main())
