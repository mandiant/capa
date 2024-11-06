import sys
import json
import logging
import sqlite3
import argparse
from typing import Iterator, Optional
from pathlib import Path
from dataclasses import dataclass

import pefile
import lancelot
import networkx as nx
import lancelot.be2utils
from lancelot.be2utils import AddressSpace, BinExport2Index, ReadMemoryError
from lancelot.be2utils.binexport2_pb2 import BinExport2

import capa.main

logger = logging.getLogger(__name__)


def is_vertex_type(vertex: BinExport2.CallGraph.Vertex, type_: BinExport2.CallGraph.Vertex.Type.ValueType) -> bool:
    return vertex.HasField("type") and vertex.type == type_


def is_vertex_thunk(vertex: BinExport2.CallGraph.Vertex) -> bool:
    return is_vertex_type(vertex, BinExport2.CallGraph.Vertex.Type.THUNK)


THUNK_CHAIN_DEPTH_DELTA = 5


def compute_thunks(be2: BinExport2, idx: BinExport2Index) -> dict[int, int]:
    # from thunk address to target function address
    thunks: dict[int, int] = {}

    for addr, vertex_idx in idx.vertex_index_by_address.items():
        vertex: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[vertex_idx]
        if not is_vertex_thunk(vertex):
            continue

        curr_vertex_idx: int = vertex_idx
        for _ in range(THUNK_CHAIN_DEPTH_DELTA):
            thunk_callees: list[int] = idx.callees_by_vertex_index[curr_vertex_idx]
            # if this doesn't hold, then it doesn't seem like this is a thunk,
            # because either, len is:
            #    0 and the thunk doesn't point to anything, such as `jmp eax`, or
            #   >1 and the thunk may end up at many functions.

            if not thunk_callees:
                # maybe we have an indirect jump, like `jmp eax`
                # that we can't actually resolve here.
                break

            assert len(thunk_callees) == 1, f"thunk @ {hex(addr)} failed"

            thunked_vertex_idx: int = thunk_callees[0]
            thunked_vertex: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[thunked_vertex_idx]

            if not is_vertex_thunk(thunked_vertex):
                assert thunked_vertex.HasField("address")

                thunks[addr] = thunked_vertex.address
                break

            curr_vertex_idx = thunked_vertex_idx

    return thunks


def read_string(address_space: AddressSpace, address: int) -> Optional[str]:
    try:
        # if at end of segment then there might be an overrun here.
        buf: bytes = address_space.read_memory(address, 0x100)

    except ReadMemoryError:
        logger.debug("failed to read memory: 0x%x", address)
        return None

    # note: we *always* break after the first iteration
    for s in capa.features.extractors.strings.extract_ascii_strings(buf):
        if s.offset != 0:
            break

        return s.s

    # note: we *always* break after the first iteration
    for s in capa.features.extractors.strings.extract_unicode_strings(buf):
        if s.offset != 0:
            break

        return s.s

    return None


@dataclass
class AssemblageRow:
    # from table: binaries
    binary_id: int
    file_name: str
    platform: str
    build_mode: str
    toolset_version: str
    github_url: str
    optimization: str
    repo_last_update: int
    size: int
    path: str
    license: str
    binary_hash: str
    repo_commit_hash: str
    # from table: functions
    function_id: int
    function_name: str
    function_hash: str
    top_comments: str
    source_codes: str
    prototype: str
    _source_file: str
    # from table: rvas
    rva_id: int
    start_rva: int
    end_rva: int

    @property
    def source_file(self):
        # cleanup some extra metadata provided by assemblage
        return self._source_file.partition(" (MD5: ")[0].partition(" (0x3: ")[0]


class Assemblage:
    conn: sqlite3.Connection
    samples: Path

    def __init__(self, db: Path, samples: Path):
        super().__init__()

        self.db = db
        self.samples = samples

        self.conn = sqlite3.connect(self.db)
        with self.conn:
            self.conn.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA busy_timeout = 5000;
                PRAGMA cache_size = -20000; -- 20MB
                PRAGMA foreign_keys = true;
                PRAGMA temp_store = memory;

                BEGIN IMMEDIATE TRANSACTION;
                CREATE INDEX IF NOT EXISTS idx__functions__binary_id ON functions (binary_id);
                CREATE INDEX IF NOT EXISTS idx__rvas__function_id ON rvas (function_id);

                CREATE VIEW IF NOT EXISTS assemblage AS
                SELECT
                    binaries.id AS binary_id,
                    binaries.file_name AS file_name,
                    binaries.platform AS platform,
                    binaries.build_mode AS build_mode,
                    binaries.toolset_version AS toolset_version,
                    binaries.github_url AS github_url,
                    binaries.optimization AS optimization,
                    binaries.repo_last_update AS repo_last_update,
                    binaries.size AS size,
                    binaries.path AS path,
                    binaries.license AS license,
                    binaries.hash AS hash,
                    binaries.repo_commit_hash AS repo_commit_hash,

                    functions.id AS function_id,
                    functions.name AS function_name,
                    functions.hash AS function_hash,
                    functions.top_comments AS top_comments,
                    functions.source_codes AS source_codes,
                    functions.prototype AS prototype,
                    functions.source_file AS source_file,

                    rvas.id AS rva_id,
                    rvas.start AS start_rva,
                    rvas.end AS end_rva
                FROM binaries
                JOIN functions ON binaries.id = functions.binary_id
                JOIN rvas ON functions.id = rvas.function_id;
            """
            )

    def get_row_by_binary_id(self, binary_id: int) -> AssemblageRow:
        with self.conn:
            cur = self.conn.execute("SELECT * FROM assemblage WHERE binary_id = ? LIMIT 1;", (binary_id,))
            return AssemblageRow(*cur.fetchone())

    def get_rows_by_binary_id(self, binary_id: int) -> Iterator[AssemblageRow]:
        with self.conn:
            cur = self.conn.execute("SELECT * FROM assemblage WHERE binary_id = ?;", (binary_id,))
            row = cur.fetchone()
            while row:
                yield AssemblageRow(*row)
                row = cur.fetchone()

    def get_path_by_binary_id(self, binary_id: int) -> Path:
        with self.conn:
            cur = self.conn.execute("""SELECT path FROM assemblage WHERE binary_id = ? LIMIT 1""", (binary_id,))
            return self.samples / cur.fetchone()[0]

    def get_pe_by_binary_id(self, binary_id: int) -> pefile.PE:
        path = self.get_path_by_binary_id(binary_id)
        return pefile.PE(data=path.read_bytes(), fast_load=True)


def generate_main(args: argparse.Namespace) -> int:
    if not args.assemblage_database.is_file():
        raise ValueError("database doesn't exist")

    db = Assemblage(args.assemblage_database, args.assemblage_directory)

    @dataclass
    class Function:
        file: str
        name: str
        start_rva: int
        end_rva: int

    functions = [
        Function(
            file=m.source_file,
            name=m.function_name,
            start_rva=m.start_rva,
            end_rva=m.end_rva,
        )
        for m in db.get_rows_by_binary_id(args.binary_id)
    ]

    pe = db.get_pe_by_binary_id(args.binary_id)
    base_address: int = pe.OPTIONAL_HEADER.ImageBase

    pe_path = db.get_path_by_binary_id(args.binary_id)
    be2: BinExport2 = lancelot.get_binexport2_from_bytes(
        pe_path.read_bytes(), function_hints=[base_address + function.start_rva for function in functions]
    )

    idx = lancelot.be2utils.BinExport2Index(be2)
    address_space = lancelot.be2utils.AddressSpace.from_pe(pe, base_address)
    thunks = compute_thunks(be2, idx)

    g = nx.MultiDiGraph()

    for flow_graph in be2.flow_graph:
        datas: set[int] = set()
        callees: set[str] = set()

        entry_basic_block_index: int = flow_graph.entry_basic_block_index
        flow_graph_address: int = idx.get_basic_block_address(entry_basic_block_index)

        for basic_block_index in flow_graph.basic_block_index:
            basic_block: BinExport2.BasicBlock = be2.basic_block[basic_block_index]

            for instruction_index, instruction, _ in idx.basic_block_instructions(basic_block):
                for addr in instruction.call_target:
                    addr = thunks.get(addr, addr)

                    if addr not in idx.vertex_index_by_address:
                        # disassembler did not define function at address
                        logger.debug("0x%x is not a vertex", addr)
                        continue

                    vertex_idx: int = idx.vertex_index_by_address[addr]
                    vertex: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[vertex_idx]

                    callees.add(vertex.address)

                for data_reference_index in idx.data_reference_index_by_source_instruction_index.get(
                    instruction_index, []
                ):
                    data_reference: BinExport2.DataReference = be2.data_reference[data_reference_index]
                    data_reference_address: int = data_reference.address

                    if data_reference_address in idx.insn_address_by_index:
                        # appears to be code
                        continue

                    datas.add(data_reference_address)

        vertex_index = idx.vertex_index_by_address[flow_graph_address]
        name = idx.get_function_name_by_vertex(vertex_index)

        g.add_node(
            flow_graph_address,
            address=flow_graph_address,
            type="function",
        )
        if datas or callees:
            logger.info("%s @ 0x%X:", name, flow_graph_address)

            for data in sorted(datas):
                logger.info("  - 0x%X", data)
                g.add_node(
                    data,
                    address=data,
                    type="data",
                )
                g.add_edge(
                    flow_graph_address,
                    data,
                    key="reference",
                    source_address=flow_graph_address,
                    destination_address=data,
                )

            for callee in sorted(callees):
                logger.info("  - %s", idx.get_function_name_by_address(callee))

                g.add_node(
                    callee,
                    address=callee,
                    type="function",
                )
                g.add_edge(
                    flow_graph_address,
                    callee,
                    key="call",
                    source_address=flow_graph_address,
                    destination_address=callee,
                )

        else:
            logger.info("%s @ 0x%X: (none)", name, flow_graph_address)

    for section in pe.sections:
        # within each section, emit a neighbor edge for each pair of neighbors.

        section_nodes = [
            node
            for node, attrs in g.nodes(data=True)
            if (section.VirtualAddress + base_address)
            <= attrs["address"]
            < (base_address + section.VirtualAddress + section.Misc_VirtualSize)
        ]

        for i in range(1, len(section_nodes)):
            a = section_nodes[i - 1]
            b = section_nodes[i]

            g.add_edge(
                a,
                b,
                key="neighbor",
                source_address=a,
                destination_address=b,
            )

    for function in functions:
        g.nodes[base_address + function.start_rva]["name"] = function.name
        g.nodes[base_address + function.start_rva]["file"] = function.file

    # rename unknown functions like: sub_401000
    for n, attrs in g.nodes(data=True):
        if attrs["type"] != "function":
            continue
        if "name" in attrs:
            continue
        attrs["name"] = f"sub_{n:x}"

    # assign human-readable repr to add nodes
    # assign is_import=bool to functions
    # assign is_string=bool to datas
    for n, attrs in g.nodes(data=True):
        match attrs["type"]:
            case "function":
                attrs["repr"] = attrs["name"]
                attrs["is_import"] = "!" in attrs["name"]
            case "data":
                if string := read_string(address_space, n):
                    attrs["repr"] = json.dumps(string)
                    attrs["is_string"] = True
                else:
                    attrs["repr"] = f"data_{n:x}"
                    attrs["is_string"] = False

    for line in nx.generate_gexf(g):
        print(line)

    # db.conn.close()
    return 0


def cluster_main(args: argparse.Namespace) -> int:
    if not args.graph.is_file():
        raise ValueError("graph file doesn't exist")

    g = nx.read_gexf(args.graph)

    communities = nx.algorithms.community.louvain_communities(g)
    for i, community in enumerate(communities):
        print(f"[{i}]:")
        for node in community:
            if "name" in g.nodes[node]:
                print(f"  - {hex(int(node, 0))}: {g.nodes[node]['file']}")
            else:
                print(f"  - {hex(int(node, 0))}")

    return 0


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Identify object boundaries in compiled programs")
    capa.main.install_common_args(parser, wanted={})
    subparsers = parser.add_subparsers(title="subcommands", required=True)

    generate_parser = subparsers.add_parser("generate", help="generate graph for a sample")
    generate_parser.add_argument("assemblage_database", type=Path, help="path to Assemblage database")
    generate_parser.add_argument("assemblage_directory", type=Path, help="path to Assemblage samples directory")
    generate_parser.add_argument("binary_id", type=int, help="primary key of binary to inspect")
    generate_parser.set_defaults(func=generate_main)

    cluster_parser = subparsers.add_parser("cluster", help="cluster an existing graph")
    cluster_parser.add_argument("graph", type=Path, help="path to a graph file")
    cluster_parser.set_defaults(func=cluster_main)

    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    logging.getLogger("goblin.pe").setLevel(logging.WARNING)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
