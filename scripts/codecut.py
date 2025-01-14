import os
import sys
import json
import logging
import sqlite3
import argparse
import subprocess
from typing import Iterator, Optional, Literal
from pathlib import Path
from dataclasses import dataclass
from multiprocessing import Pool

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

            if len(thunk_callees) != 1:
                for thunk_callee in thunk_callees:
                    logger.warning("%s", hex(be2.call_graph.vertex[thunk_callee].address))
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

    def get_binary_ids(self) -> Iterator[int]:
        with self.conn:
            cur = self.conn.execute("SELECT DISTINCT binary_id FROM assemblage ORDER BY binary_id ASC;")
            row = cur.fetchone()
            while row:
                yield row[0]
                row = cur.fetchone()


def generate_main(args: argparse.Namespace) -> int:
    if not args.assemblage_database.is_file():
        raise ValueError("database doesn't exist")

    db = Assemblage(args.assemblage_database, args.assemblage_directory)

    pe = db.get_pe_by_binary_id(args.binary_id)
    base_address: int = pe.OPTIONAL_HEADER.ImageBase

    functions_by_address = {
        base_address + function.start_rva: function for function in db.get_rows_by_binary_id(args.binary_id)
    }

    hash = db.get_row_by_binary_id(args.binary_id).binary_hash

    def make_node_id(address: int) -> str:
        return f"{hash}:{address:x}"

    pe_path = db.get_path_by_binary_id(args.binary_id)
    be2: BinExport2 = lancelot.get_binexport2_from_bytes(
        pe_path.read_bytes(), function_hints=list(functions_by_address.keys())
    )

    idx = lancelot.be2utils.BinExport2Index(be2)
    address_space = lancelot.be2utils.AddressSpace.from_pe(pe, base_address)
    thunks = compute_thunks(be2, idx)

    g = nx.MultiDiGraph()

    # ensure all functions from ground truth have an entry
    for address, function in functions_by_address.items():
        g.add_node(
            make_node_id(address),
            address=address,
            type="function",
        )

    for flow_graph in be2.flow_graph:
        datas: set[int] = set()
        callees: set[int] = set()

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
            make_node_id(flow_graph_address),
            address=flow_graph_address,
            type="function",
        )
        if datas or callees:
            logger.info("%s @ 0x%X:", name, flow_graph_address)

            for data_address in sorted(datas):
                logger.info("  - 0x%X", data_address)
                # TODO: check if this is already a function
                g.add_node(
                    make_node_id(data_address),
                    address=data_address,
                    type="data",
                )
                g.add_edge(
                    make_node_id(flow_graph_address),
                    make_node_id(data_address),
                    key="reference",
                )

            for callee in sorted(callees):
                logger.info("  - %s", idx.get_function_name_by_address(callee))

                g.add_node(
                    make_node_id(callee),
                    address=callee,
                    type="function",
                )
                g.add_edge(
                    make_node_id(flow_graph_address),
                    make_node_id(callee),
                    key="call",
                )

        else:
            logger.info("%s @ 0x%X: (none)", name, flow_graph_address)

    # set ground truth node attributes from source data
    for node, attrs in g.nodes(data=True):
        if attrs["type"] != "function":
            continue

        if f := functions_by_address.get(attrs["address"]):
            attrs["name"] = f.function_name
            attrs["file"] = f.file_name

    for section in pe.sections:
        # Within each section, emit a neighbor edge for each pair of neighbors.
        # Neighbors only link nodes of the same type, because assemblage doesn't
        # have ground truth for data items, so we don't quite know where to split.
        # Consider this situation:
        #
        #   moduleA::func1
        #    --- cut ---
        #   moduleB::func1
        #
        # that one is ok, but this is hard:
        #
        #   moduleA::func1
        #    --- cut??? ---
        #   dataZ
        #    --- or cut here??? ---
        #   moduleB::func1
        #
        # Does the cut go before or after dataZ?
        # So, we only have neighbor graphs within functions, and within datas.
        # For datas, we don't allow interspersed functions.

        section_nodes = sorted(
            [
                (node, attrs)
                for node, attrs in g.nodes(data=True)
                if (section.VirtualAddress + base_address)
                <= attrs["address"]
                < (base_address + section.VirtualAddress + section.Misc_VirtualSize)
            ],
            key=lambda p: p[1]["address"],
        )

        # add neighbor edges between data items.
        # the data items must not be separated by any functions.
        for i in range(1, len(section_nodes)):
            a, a_attrs = section_nodes[i - 1]
            b, b_attrs = section_nodes[i]

            if a_attrs["type"] != "data":
                continue

            if b_attrs["type"] != "data":
                continue

            g.add_edge(a, b, key="neighbor")
            g.add_edge(b, a, key="neighbor")

        section_functions = [
            (node, attrs)
            for node, attrs in section_nodes
            if attrs["type"] == "function"
            # we only have ground truth for the known functions
            # so only consider those in the function neighbor graph.
            and attrs["address"] in functions_by_address
        ]

        # add neighbor edges between functions.
        # we drop the potentially interspersed data items before computing these edges.
        for i in range(1, len(section_functions)):
            a, a_attrs = section_functions[i - 1]
            b, b_attrs = section_functions[i]
            is_boundary = a_attrs["file"] == b_attrs["file"]

            # edge attribute: is_source_file_boundary
            g.add_edge(a, b, key="neighbor", is_source_file_boundary=is_boundary)
            g.add_edge(b, a, key="neighbor", is_source_file_boundary=is_boundary)

    # rename unknown functions like: sub_401000
    for n, attrs in g.nodes(data=True):
        if attrs["type"] != "function":
            continue

        if "name" in attrs:
            continue

        attrs["name"] = f"sub_{attrs['address']:x}"

    # assign human-readable repr to add nodes
    # assign is_import=bool to functions
    # assign is_string=bool to datas
    for n, attrs in g.nodes(data=True):
        match attrs["type"]:
            case "function":
                attrs["repr"] = attrs["name"]
                attrs["is_import"] = "!" in attrs["name"]
            case "data":
                if string := read_string(address_space, attrs["address"]):
                    attrs["repr"] = json.dumps(string)
                    attrs["is_string"] = True
                else:
                    attrs["repr"] = f"data_{attrs['address']:x}"
                    attrs["is_string"] = False

    for line in nx.generate_gexf(g):
        print(line)

    # db.conn.close()
    return 0


def _worker(args):

    assemblage_database: Path
    assemblage_directory: Path
    graph_file: Path
    binary_id: int

    (assemblage_database, assemblage_directory, graph_file, binary_id) = args
    if graph_file.is_file():
        return

    logger.info("processing: %d", binary_id)
    process = subprocess.run(
        ["python", __file__, "--debug", "generate", assemblage_database, assemblage_directory, str(binary_id)],
        capture_output=True,
        encoding="utf-8",
    )
    if process.returncode != 0:
        logger.warning("failed: %d", binary_id)
        logger.debug("%s", process.stderr)
        return

    graph_file.parent.mkdir(exist_ok=True)
    graph = process.stdout
    graph_file.write_text(graph)


def generate_all_main(args: argparse.Namespace) -> int:
    if not args.assemblage_database.is_file():
        raise ValueError("database doesn't exist")

    db = Assemblage(args.assemblage_database, args.assemblage_directory)

    binary_ids = list(db.get_binary_ids())

    with Pool(args.num_workers) as p:
        _ = list(
            p.imap_unordered(
                _worker,
                (
                    (
                        args.assemblage_database,
                        args.assemblage_directory,
                        args.output_directory / str(binary_id) / "graph.gexf",
                        binary_id,
                    )
                    for binary_id in binary_ids
                ),
            )
        )

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


# uv pip install torch --index-url https://download.pytorch.org/whl/cpu
# uv pip install torch-geometric pandas numpy scikit-learn
# import torch  # do this on-demand below, because its slow
# from torch_geometric.data import HeteroData


@dataclass
class NodeType:
    type: str
    attributes: dict[str, Literal[False] | Literal[""] | Literal[0] | float]


@dataclass
class EdgeType:
    key: str
    source_type: NodeType
    destination_type: NodeType
    attributes: dict[str, Literal[False] | Literal[""] | Literal[0] | float]


NODE_TYPES = {
    node.type: node
    for node in [
        NodeType(
            type="function",
            attributes={
                "is_import": False,
                "does_reference_string": False,
                # "ground_truth": False,
                # unused:
                # - repr: str
                # - address: int
                # - name: str
                # - file: str
            },
        ),
        NodeType(
            type="data",
            attributes={
                "is_string": False,
                # unused:
                # - repr: str
                # - address: int
            },
        ),
    ]
}

FUNCTION_NODE = NODE_TYPES["function"]
DATA_NODE = NODE_TYPES["data"]

EDGE_TYPES = {
    (edge.source_type.type, edge.key, edge.destination_type.type): edge
    for edge in [
        EdgeType(
            key="call",
            source_type=FUNCTION_NODE,
            destination_type=FUNCTION_NODE,
            attributes={},
        ),
        EdgeType(
            key="reference",
            source_type=FUNCTION_NODE,
            destination_type=DATA_NODE,
            attributes={},
        ),
        EdgeType(
            # When functions reference other functions as data,
            # such as passing a function pointer as a callback.
            #
            # Example:
            #   __scrt_set_unhandled_exception_filter > reference > __scrt_unhandled_exception_filter
            key="reference",
            source_type=FUNCTION_NODE,
            destination_type=FUNCTION_NODE,
            attributes={},
        ),
        EdgeType(
            key="neighbor",
            source_type=FUNCTION_NODE,
            destination_type=FUNCTION_NODE,
            attributes={
                # this is the attribute to predict (ultimately)
                # "is_source_file_boundary": False,
                "distance": 1,
            },
        ),
        EdgeType(
            key="neighbor",
            source_type=DATA_NODE,
            destination_type=DATA_NODE,
            # attributes={
            # },
            attributes={
                # this is the attribute to predict (ultimately)
                # "is_source_file_boundary": False,
                "distance": 1,
            },
        ),
    ]
}


@dataclass
class LoadedGraph:
    data: "HeteroData"

    # map from node type to:
    # map from node id (str) to node index (int), and node index (int) to node id (str).
    mapping: dict[str, dict[str | int, int | str]]


def load_graph(g: nx.MultiDiGraph) -> LoadedGraph:
    import torch
    from torch_geometric.data import HeteroData

    # Our networkx graph identifies nodes by str ("sha256:address").
    # Torch identifies nodes by index, from 0 to #nodes, for each type of node.
    # Map one to another.
    node_indexes_by_node: dict[str, dict[str, int]] = {n: {} for n in NODE_TYPES.keys()}
    # Because the types are different (str and int),
    # here's a single mapping where the type of the key implies
    # the sort of lookup you're doing (by index (int) or by node id (str)).
    node_mapping: dict[str, dict[str | int, int | str]] = {n: {} for n in NODE_TYPES.keys()}
    for node_type in NODE_TYPES.keys():
        def is_this_node_type(node_attrs):
            node, attrs = node_attrs
            return attrs["type"] == node_type

        ns = g.nodes(data=True)
        ns = sorted(ns)
        ns = filter(is_this_node_type, ns)
        ns = map(lambda p: p[0], ns)
        for i, node in enumerate(ns):
            node_indexes_by_node[node_type][node] = i
            node_mapping[node_type][node] = i
            node_mapping[node_type][i] = node

    data = HeteroData()

    for node_type in NODE_TYPES.values():
        logger.debug("loading nodes: %s", node_type.type)

        node_indexes: list[int] = []
        attr_values: dict[str, list] = {attribute: [] for attribute in node_type.attributes.keys()}

        for node, attrs in g.nodes(data=True):
            if attrs["type"] != node_type.type:
                continue

            node_index = node_indexes_by_node[node_type.type][node]
            node_indexes.append(node_index)

            for attribute, default_value in node_type.attributes.items():
                value = attrs.get(attribute, default_value)
                attr_values[attribute].append(value)

        data[node_type.type].node_id = torch.tensor(node_indexes)
        if attr_values:
            # attribute order is implicit in the NODE_TYPES data model above.
            data[node_type.type].x = torch.stack([torch.tensor(values) for values in attr_values.values()], dim=-1).float()

    for edge_type in EDGE_TYPES.values():
        logger.debug(
             "loading edges: %s > %s > %s", 
             edge_type.source_type.type, edge_type.key, edge_type.destination_type.type
         )

        source_indexes: list[int] = []
        destination_indexes: list[int] = []
        attr_values: dict[str, list] = {attribute: [] for attribute in edge_type.attributes.keys()}

        for source, destination, key, attrs in g.edges(data=True, keys=True):
            if key != edge_type.key:
                continue
            if g.nodes[source]["type"] != edge_type.source_type.type:
                continue
            if g.nodes[destination]["type"] != edge_type.destination_type.type:
                continue

            # These are global node indexes
            # but we need to provide the node type-local index.
            # That is, functions have their own node indexes, 0 to N. data have their own node indexes, 0 to N.
            source_index = node_indexes_by_node[g.nodes[source]["type"]][source]
            destination_index = node_indexes_by_node[g.nodes[destination]["type"]][destination]

            source_indexes.append(source_index)
            destination_indexes.append(destination_index)

            for attribute, default_value in edge_type.attributes.items():
                value = attrs.get(attribute, default_value)
                attr_values[attribute].append(value)

        data[edge_type.source_type.type, edge_type.key, edge_type.destination_type.type].edge_index = torch.stack(
            [
                torch.tensor(source_indexes),
                torch.tensor(destination_indexes),
            ]
        )
        if attr_values:
            # attribute order is implicit in the EDGE_TYPES data model above.
            data[edge_type.source_type.type, edge_type.key, edge_type.destination_type.type].edge_attr = torch.stack(
                [torch.tensor(values) for values in attr_values.values()], dim=-1
            ).float()

    return LoadedGraph(
        data,
        node_mapping,
    )


def train_main(args: argparse.Namespace) -> int:
    if not args.graph.is_file():
        raise ValueError("graph file doesn't exist")

    logger.debug("loading torch")
    import torch

    import random
    import numpy as np

    seed = 42
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    logger.debug("reading graph from disk")
    g = nx.read_gexf(args.graph)

    # Initial model: learn to find functions that reference a string.
    #
    # Once this works, then we can try a more complex model (edge features),
    # and ultimately an edge classifier.
    #
    # Ground truth from existing patterns like:
    #
    #     function > references > data (:is_string=True)

    for a, b, key, attrs in g.edges(data=True, keys=True):
        match (g.nodes[a]["type"], key, g.nodes[b]["type"]):
            case ("function", "reference", "data"):

                if g.nodes[b].get("is_string"):
                    g.nodes[a]["does_reference_string"] = True
                    logger.debug("%s > reference > %s (string)", g.nodes[a]["repr"], g.nodes[b]["repr"])

            case ("function", "reference", "function"):
                # The data model supports this.
                # Like passing a function pointer as a callback
                continue
            case ("data", "reference", "data"):
                # We don't support this.
                continue
            case ("data", "reference", "function"):
                # We don't support this.
                continue
            case (_, "call", _):
                continue
            case (_, "neighbor", _):
                continue
            case _:
                print(a, b, key, attrs, g.nodes[a], g.nodes[b])
                raise ValueError("unexpected structure")

    # map existing attributes to the ground_truth attribute
    # for ease of updating the model/training.
    for node, attrs in g.nodes(data=True):
        if attrs["type"] != "function":
            continue

        attrs["ground_truth"] = attrs.get("does_reference_string", False)

    logger.debug("loading graph into torch")
    lg = load_graph(g)
    data = lg.data

    data['data'].y = torch.zeros(data['data'].num_nodes, dtype=torch.long)
    data['function'].y = torch.zeros(data['function'].num_nodes, dtype=torch.long)
    true_indices = []

    for node, attrs in g.nodes(data=True):
        if attrs.get("ground_truth"):
            print("true: ", g.nodes[node]["repr"])
            node_index = lg.mapping[attrs["type"]][node]
            print("index", attrs["type"], node_index)
            print("     ", node)
            print("     ", lg.mapping[attrs["type"]][node_index])

            true_indices.append(node_index)
            # true_indices.append(data['function'].node_id[node_index].item())
            # print("true index: ", node_index, data['function'].node_id[node_index].item())

    data['function'].y[true_indices] = 1
    print(data['function'].y)

    # TODO
    import torch_geometric.transforms as T
    data = T.ToUndirected()(data)
    # data = T.AddSelfLoops()(data)
    data = T.NormalizeFeatures()(data)

    print(data)

    from torch_geometric.nn import RGCNConv, to_hetero, SAGEConv, Linear
    import torch.nn.functional as F

    class GNN(torch.nn.Module):
        def __init__(self, hidden_channels, out_channels):
            super().__init__()
            self.conv1 = SAGEConv((-1, -1), hidden_channels)
            self.conv2 = SAGEConv((-1, -1), hidden_channels)
            self.lin = Linear(hidden_channels, out_channels)

        def forward(self, x, edge_index):
            x = self.conv1(x, edge_index).relu()
            x = self.conv2(x, edge_index)
            x = self.lin(x)
            return x

    model = GNN(hidden_channels=4, out_channels=2)
    # metadata: tuple[list of node types, list of edge types (source, key, dest)]
    model = to_hetero(model, data.metadata(), aggr='sum')
    # model.print_readable()

    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

    from sklearn.model_selection import train_test_split
    train_nodes, test_nodes = train_test_split(
        torch.arange(data['function'].num_nodes), test_size=0.2, random_state=42
    )

    train_mask = torch.zeros(data['function'].num_nodes, dtype=torch.bool)
    # train_mask[train_nodes] = True
    train_mask[:] = True

    test_mask = torch.zeros(data['function'].num_nodes, dtype=torch.bool)
    # test_mask[test_nodes] = True
    test_mask[:] = True

    data['function'].train_mask = train_mask
    data['function'].test_mask = test_mask

    logger.debug("training")
    for epoch in range(999):
        model.train()
        optimizer.zero_grad()

        # don't use edge attrs right now.
        out = model(data.x_dict, data.edge_index_dict)  # data.edge_attr_dict)

        out_function = out['function']
        y_function = data['function'].y

        mask = data['function'].train_mask

        # When classifying "function has string reference"
        # there is a major class imbalance, because 95% of function's don't reference a string,
        # so the model just learns to predict "no".
        # Therefore, weight the classes so that a "yes" prediction is much more valuable.
        class_counts = torch.bincount(data['function'].y[mask])
        class_weights = 1.0 / class_counts.float()
        class_weights = class_weights / class_weights.sum() * len(class_counts)

        # CrossEntropyLoss(): the most common choice for node classification with mutually exclusive classes.
        # BCEWithLogitsLoss(): multi-label node classification
        criterion = torch.nn.CrossEntropyLoss(weight=class_weights)

        loss = criterion(out_function[mask], y_function[mask])

        loss.backward()
        optimizer.step()

        logger.info(f'Epoch: {epoch:03d}, Loss: {loss:.4f}')
        if loss <= 0.0001:
            logger.info("no more loss")
            break

    logger.debug("evaluating")
    model.eval()
    with torch.no_grad():
        out = model(data.x_dict, data.edge_index_dict)  # TODO: edge attrs

        mask = data['function'].test_mask
        pred = torch.argmax(out['function'][mask], dim=1)
        truth = data['function'].y[mask].int()

        print("pred", pred[:32])
        print("truth", truth[:32])
        # print("index", data['function'].node_id[mask])
        # print("83: ", g.nodes[lg.mapping['function'][83]]['repr'])
        
        accuracy = (pred == truth).float().mean()

        # pred = (out[data['function'].test_mask] > 0).int().squeeze()
        # accuracy = (pred == data['function'].y[data['function'].test_mask]).float().mean()
        print(f'Accuracy: {accuracy:.4f}')

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

    num_cores = os.cpu_count() or 1
    default_workers = max(1, num_cores - 2)
    generate_all_parser = subparsers.add_parser("generate_all", help="generate graphs for all samples")
    generate_all_parser.add_argument("assemblage_database", type=Path, help="path to Assemblage database")
    generate_all_parser.add_argument("assemblage_directory", type=Path, help="path to Assemblage samples directory")
    generate_all_parser.add_argument("output_directory", type=Path, help="path to output directory")
    generate_all_parser.add_argument(
        "--num_workers", type=int, default=default_workers, help="number of workers to use"
    )
    generate_all_parser.set_defaults(func=generate_all_main)

    cluster_parser = subparsers.add_parser("cluster", help="cluster an existing graph")
    cluster_parser.add_argument("graph", type=Path, help="path to a graph file")
    cluster_parser.set_defaults(func=cluster_main)

    train_parser = subparsers.add_parser("train", help="train using an existing graph")
    train_parser.add_argument("graph", type=Path, help="path to a graph file")
    train_parser.set_defaults(func=train_main)

    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    logging.getLogger("goblin.pe").setLevel(logging.WARNING)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
