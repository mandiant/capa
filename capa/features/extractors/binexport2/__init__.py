# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""
Proto files generated via protobuf v24.4:

    protoc --python_out=. --mypy_out=. binexport2.proto
"""
import io
import hashlib
import logging
import contextlib
from typing import Dict, List, Tuple, Iterator
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass

from pefile import PE
from elftools.elf.elffile import ELFFile

import capa.features.extractors.common
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


def get_binexport2(sample: Path) -> BinExport2:
    be2 = BinExport2()
    be2.ParseFromString(sample.read_bytes())
    return be2


def compute_common_prefix_length(m: str, n: str) -> int:
    # ensure #m < #n
    if len(n) < len(m):
        m, n = n, m

    for i, c in enumerate(m):
        if n[i] != c:
            return i

    return len(m)


def get_sample_from_binexport2(input_file: Path, be2: BinExport2, search_paths: List[Path]) -> Path:
    """attempt to find the sample file, given a BinExport2 file.

    searches in the same directory as the BinExport2 file, and then in search_paths.
    """

    def filename_similarity_key(p: Path):
        # note closure over input_file.
        # sort first by length of common prefix, then by name (for stability)
        return (compute_common_prefix_length(p.name, input_file.name), p.name)

    wanted_sha256 = be2.meta_information.executable_id.lower()

    input_directory = input_file.parent
    siblings = [p for p in input_directory.iterdir() if p.is_file()]
    siblings.sort(key=filename_similarity_key, reverse=True)
    for sibling in siblings:
        # e.g. with open IDA files in the same directory on Windows
        with contextlib.suppress(PermissionError):
            if hashlib.sha256(sibling.read_bytes()).hexdigest().lower() == wanted_sha256:
                return sibling

    for search_path in search_paths:
        candidates = [p for p in search_path.iterdir() if p.is_file()]
        candidates.sort(key=filename_similarity_key, reverse=True)
        for candidate in candidates:
            with contextlib.suppress(PermissionError):
                if hashlib.sha256(candidate.read_bytes()).hexdigest().lower() == wanted_sha256:
                    return candidate

    raise ValueError("cannot find sample")


class BinExport2Index:
    def __init__(self, be2: BinExport2):
        self.be2 = be2

        self.callers_by_vertex_index: Dict[int, List[int]] = defaultdict(list)
        self.callees_by_vertex_index: Dict[int, List[int]] = defaultdict(list)

        # note: flow graph != call graph (vertex)
        self.flow_graph_index_by_address: Dict[int, int] = {}
        self.flow_graph_address_by_index: Dict[int, int] = {}

        # edges that come from the given basic block
        self.source_edges_by_basic_block_index: Dict[int, List[BinExport2.FlowGraph.Edge]] = defaultdict(list)
        # edges that end up at the given basic block
        self.target_edges_by_basic_block_index: Dict[int, List[BinExport2.FlowGraph.Edge]] = defaultdict(list)

        self.vertex_index_by_address: Dict[int, int] = {}

        self.data_reference_index_by_source_instruction_index: Dict[int, List[int]] = defaultdict(list)
        self.data_reference_index_by_target_address: Dict[int, List[int]] = defaultdict(list)
        self.string_reference_index_by_source_instruction_index: Dict[int, List[int]] = defaultdict(list)

        self.insn_address_by_index: Dict[int, int] = {}

        # must index instructions first
        self._index_insn_addresses()
        self._index_vertex_edges()
        self._index_flow_graph_nodes()
        self._index_flow_graph_edges()
        self._index_call_graph_vertices()
        self._index_data_references()
        self._index_string_references()

    def get_insn_address(self, insn_index: int) -> int:
        assert insn_index in self.insn_address_by_index, f"insn must be indexed, missing {insn_index}"
        return self.insn_address_by_index[insn_index]

    def get_basic_block_address(self, basic_block_index: int) -> int:
        basic_block = self.be2.basic_block[basic_block_index]
        first_instruction_index = next(self.instruction_indices(basic_block))

        return self.get_insn_address(first_instruction_index)

    def _index_vertex_edges(self):
        for edge in self.be2.call_graph.edge:
            if not edge.source_vertex_index:
                continue
            if not edge.target_vertex_index:
                continue

            self.callers_by_vertex_index[edge.target_vertex_index].append(edge.source_vertex_index)
            self.callees_by_vertex_index[edge.source_vertex_index].append(edge.target_vertex_index)

    def _index_flow_graph_nodes(self):
        for flow_graph_index, flow_graph in enumerate(self.be2.flow_graph):
            function_address = self.get_basic_block_address(flow_graph.entry_basic_block_index)
            self.flow_graph_index_by_address[function_address] = flow_graph_index
            self.flow_graph_address_by_index[flow_graph_index] = function_address

    def _index_flow_graph_edges(self):
        for flow_graph in self.be2.flow_graph:
            for edge in flow_graph.edge:
                if not edge.HasField("source_basic_block_index") or not edge.HasField("target_basic_block_index"):
                    continue

                self.source_edges_by_basic_block_index[edge.source_basic_block_index].append(edge)
                self.target_edges_by_basic_block_index[edge.target_basic_block_index].append(edge)

    def _index_call_graph_vertices(self):
        for vertex_index, vertex in enumerate(self.be2.call_graph.vertex):
            if not vertex.HasField("address"):
                continue

            vertex_address = vertex.address
            self.vertex_index_by_address[vertex_address] = vertex_index

    def _index_data_references(self):
        for data_reference_index, data_reference in enumerate(self.be2.data_reference):
            self.data_reference_index_by_source_instruction_index[data_reference.instruction_index].append(
                data_reference_index
            )
            self.data_reference_index_by_target_address[data_reference.address].append(data_reference_index)

    def _index_string_references(self):
        for string_reference_index, string_reference in enumerate(self.be2.string_reference):
            self.string_reference_index_by_source_instruction_index[string_reference.instruction_index].append(
                string_reference_index
            )

    def _index_insn_addresses(self):
        # see https://github.com/google/binexport/blob/39f6445c232bb5caf5c4a2a996de91dfa20c48e8/binexport.cc#L45
        if len(self.be2.instruction) == 0:
            return

        assert self.be2.instruction[0].HasField("address"), "first insn must have explicit address"

        addr = 0
        next_addr = 0
        for idx, insn in enumerate(self.be2.instruction):
            if insn.HasField("address"):
                addr = insn.address
                next_addr = addr + len(insn.raw_bytes)
            else:
                addr = next_addr
                next_addr += len(insn.raw_bytes)
            self.insn_address_by_index[idx] = addr

    @staticmethod
    def instruction_indices(basic_block: BinExport2.BasicBlock) -> Iterator[int]:
        """
        For a given basic block, enumerate the instruction indices.
        """
        for index_range in basic_block.instruction_index:
            if not index_range.HasField("end_index"):
                yield index_range.begin_index
                continue
            else:
                yield from range(index_range.begin_index, index_range.end_index)

    def basic_block_instructions(
        self, basic_block: BinExport2.BasicBlock
    ) -> Iterator[Tuple[int, BinExport2.Instruction, int]]:
        """
        For a given basic block, enumerate the instruction indices,
        the instruction instances, and their addresses.
        """
        for instruction_index in self.instruction_indices(basic_block):
            instruction = self.be2.instruction[instruction_index]
            instruction_address = self.get_insn_address(instruction_index)

            yield instruction_index, instruction, instruction_address

    def get_function_name_by_vertex(self, vertex_index: int) -> str:
        vertex = self.be2.call_graph.vertex[vertex_index]
        name = f"sub_{vertex.address:x}"
        if vertex.HasField("mangled_name"):
            name = vertex.mangled_name

        if vertex.HasField("demangled_name"):
            name = vertex.demangled_name

        if vertex.HasField("library_index"):
            library = self.be2.library[vertex.library_index]
            if library.HasField("name"):
                name = f"{library.name}!{name}"

        return name

    def get_function_name_by_address(self, address: int) -> str:
        if address not in self.vertex_index_by_address:
            return ""

        vertex_index = self.vertex_index_by_address[address]
        return self.get_function_name_by_vertex(vertex_index)


class BinExport2Analysis:
    def __init__(self, be2: BinExport2, idx: BinExport2Index, buf: bytes):
        self.be2 = be2
        self.idx = idx
        self.buf = buf
        self.base_address: int = 0

        self._find_base_address()

    def _find_base_address(self):
        sections_with_perms = filter(lambda s: s.flag_r or s.flag_w or s.flag_x, self.be2.section)
        # assume the lowest address is the base address.
        # this works as long as BinExport doesn't record other
        # libraries mapped into memory.
        self.base_address = min(s.address for s in sections_with_perms)


@dataclass
class MemoryRegion:
    # location of the bytes, potentially relative to a base address
    address: int
    buf: bytes

    @property
    def end(self) -> int:
        return self.address + len(self.buf)

    def contains(self, address: int) -> bool:
        # note: address must be relative to any base address
        return self.address <= address < self.end


class ReadMemoryError(ValueError): ...


class AddressNotMappedError(ReadMemoryError): ...


@dataclass
class AddressSpace:
    base_address: int
    memory_regions: Tuple[MemoryRegion, ...]

    def read_memory(self, address: int, length: int) -> bytes:
        rva = address - self.base_address
        for region in self.memory_regions:
            if region.contains(rva):
                offset = rva - region.address
                return region.buf[offset : offset + length]

        raise AddressNotMappedError(address)

    @classmethod
    def from_pe(cls, pe: PE):
        base_address = pe.OPTIONAL_HEADER.ImageBase

        regions = []
        for section in pe.sections:
            address = section.VirtualAddress
            size = section.Misc_VirtualSize
            buf = section.get_data()

            if len(buf) != size:
                # pad the section with NULLs
                # assume page alignment is already handled.
                # might need more hardening here.
                buf += b"\x00" * (size - len(buf))

            regions.append(MemoryRegion(address, buf))

        return cls(base_address, tuple(regions))

    @classmethod
    def from_elf(cls, elf: ELFFile):
        regions = []

        # ELF segments are for runtime data,
        # ELF sections are for link-time data.
        for segment in elf.iter_segments():
            # assume p_align is consistent with addresses here.
            # otherwise, should harden this loader.
            segment_rva = segment.header.p_vaddr
            segment_size = segment.header.p_memsz
            segment_data = segment.data()

            if len(segment_data) < segment_size:
                # pad the section with NULLs
                # assume page alignment is already handled.
                # might need more hardening here.
                segment_data += b"\x00" * (segment_size - len(segment_data))

            regions.append(MemoryRegion(segment_rva, segment_data))

        return cls(0, tuple(regions))

    @classmethod
    def from_buf(cls, buf: bytes):
        if buf.startswith(capa.features.extractors.common.MATCH_PE):
            pe = PE(data=buf)
            return cls.from_pe(pe)
        elif buf.startswith(capa.features.extractors.common.MATCH_ELF):
            elf = ELFFile(io.BytesIO(buf))
            return cls.from_elf(elf)
        else:
            raise NotImplementedError("file format address space")


@dataclass
class AnalysisContext:
    sample_bytes: bytes
    be2: BinExport2
    idx: BinExport2Index
    analysis: BinExport2Analysis
    address_space: AddressSpace


@dataclass
class FunctionContext:
    ctx: AnalysisContext
    flow_graph_index: int


@dataclass
class BasicBlockContext:
    basic_block_index: int


@dataclass
class InstructionContext:
    instruction_index: int
