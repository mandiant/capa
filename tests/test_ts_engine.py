from typing import List, Tuple

import pytest
from fixtures import *
from tree_sitter import Node, Tree, Parser

from capa.features.address import FileOffsetRangeAddress
from capa.features.extractors.script import LANG_CS
from capa.features.extractors.ts.query import QueryBinding
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine


def do_test_ts_engine_init(engine: TreeSitterExtractorEngine):
    assert engine.language == LANG_CS
    assert isinstance(engine.query, QueryBinding)
    assert isinstance(engine.import_signatures, set) and len(engine.import_signatures) > 0
    assert isinstance(engine.path, str) and len(engine.path) > 0
    assert isinstance(engine.buf, bytes) and len(engine.buf) > 0
    assert isinstance(engine.parser, Parser)
    assert isinstance(engine.tree, Tree)
    assert isinstance(engine.get_default_address(), FileOffsetRangeAddress)
    addr = engine.get_default_address()
    assert addr.start_byte == engine.tree.root_node.start_byte and addr.end_byte == engine.tree.root_node.end_byte


def do_test_ts_engine_object_parsing(engine: TreeSitterExtractorEngine, expected_list: List[Tuple[str, str]]):
    for (node, name), (expected_range, expected_id_range) in zip(
        engine.get_new_objects(engine.tree.root_node), expected_list
    ):
        assert isinstance(node, Node)
        assert name == "object.new"
        assert engine.get_range(node) == expected_range
        assert isinstance(engine.get_address(node), FileOffsetRangeAddress)
        addr = engine.get_address(node)
        assert addr.start_byte == node.start_byte and addr.end_byte == node.end_byte
        assert engine.get_range(engine.get_object_id(node)) == expected_id_range

    for node, (_, expected_id_range) in zip(engine.get_new_object_ids(engine.tree.root_node), expected_list):
        assert isinstance(node, Node)
        assert engine.get_range(node) == expected_id_range
        assert isinstance(engine.get_address(node), FileOffsetRangeAddress)
        addr = engine.get_address(node)
        assert addr.start_byte == node.start_byte and addr.end_byte == node.end_byte


def do_test_ts_engine_function_definition_parsing(
    engine: TreeSitterExtractorEngine, expected_list: List[Tuple[str, str]]
):
    for (node, name), (expected_range, expected_id_range) in zip(
        engine.get_function_definitions(engine.tree.root_node), expected_list
    ):
        assert isinstance(node, Node)
        assert name == "function.definition"
        assert engine.get_range(node).startswith(expected_range)
        assert isinstance(engine.get_address(node), FileOffsetRangeAddress)
        addr = engine.get_address(node)
        assert addr.start_byte == node.start_byte and addr.end_byte == node.end_byte
        assert engine.get_range(engine.get_function_definition_id(node)) == expected_id_range

    for node, (_, expected_id_range) in zip(engine.get_function_definition_ids(engine.tree.root_node), expected_list):
        assert isinstance(node, Node)
        assert engine.get_range(node) == expected_id_range
        assert isinstance(engine.get_address(node), FileOffsetRangeAddress)
        addr = engine.get_address(node)
        assert addr.start_byte == node.start_byte and addr.end_byte == node.end_byte


@parametrize(
    "engine_str,expected_dict",
    [
        (
            "cs_f397cb_extractor_engine",
            {
                "global objects": [
                    (
                        'new Diagnostics.ProcessStartInfo("cmd", "/c " + Request.Form["c"])',
                        "Diagnostics.ProcessStartInfo",
                    ),
                    ("new System.Diagnostics.Process()", "System.Diagnostics.Process"),
                ],
                "global function definitions": [
                    ("void die()", "die"),
                    ("void Page_Load(object sender, System.EventArgs e)", "Page_Load"),
                ],
            },
        ),
    ],
)
def test_ts_engine(request: pytest.FixtureRequest, engine_str: str, expected_dict: dict):
    engine: TreeSitterExtractorEngine = request.getfixturevalue(engine_str)
    do_test_ts_engine_init(engine)
    do_test_ts_engine_object_parsing(engine, expected_dict["global objects"])
    do_test_ts_engine_function_definition_parsing(engine, expected_dict["global function definitions"])
