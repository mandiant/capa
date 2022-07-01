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


def do_test_range(engine: TreeSitterExtractorEngine, node: Node, expected_range: str, startswith: bool = False):
    assert engine.get_range(node).startswith(expected_range) if startswith else engine.get_range(node) == expected_range


def do_test_id_range(engine: TreeSitterExtractorEngine, node: Node, expected_id_range: str, startswith: bool = False):
    do_test_range(engine, engine.get_object_id(node), expected_id_range, startswith)


def do_test_range_address(engine: TreeSitterExtractorEngine, node: Node):
    assert isinstance(engine.get_address(node), FileOffsetRangeAddress)
    addr = engine.get_address(node)
    assert addr.start_byte == node.start_byte and addr.end_byte == node.end_byte


def do_test_ts_engine_object_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[Tuple[str, str]]
):
    for (node, name), (expected_range, expected_id_range) in zip(engine.get_new_objects(root_node), expected_list):
        assert isinstance(node, Node)
        assert name == "object.new"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)
        do_test_range(engine, engine.get_object_id(node), expected_id_range)

    for node, (_, expected_id_range) in zip(engine.get_new_object_ids(root_node), expected_list):
        assert isinstance(node, Node)
        do_test_range(engine, node, expected_id_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_function_definition_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[Tuple[str, str]]
):
    for (node, name), (expected_range, expected_id_range) in zip(
        engine.get_function_definitions(root_node), expected_list
    ):
        assert isinstance(node, Node)
        assert name == "function.definition"
        do_test_range(engine, node, expected_range, startswith=True)
        do_test_range_address(engine, node)
        do_test_range(engine, engine.get_function_definition_id(node), expected_id_range)

    for node, (_, expected_id_range) in zip(engine.get_function_definition_ids(root_node), expected_list):
        assert isinstance(node, Node)
        do_test_range(engine, node, expected_id_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_function_call_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[Tuple[str, str]]
):
    for (node, name), (expected_range, expected_id_range) in zip(engine.get_function_calls(root_node), expected_list):
        assert isinstance(node, Node)
        assert name == "function.call"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)
        do_test_range(engine, engine.get_function_call_id(node), expected_id_range)

    for node, (_, expected_id_range) in zip(engine.get_function_call_ids(root_node), expected_list):
        assert isinstance(node, Node)
        do_test_range(engine, node, expected_id_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_string_literals_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: Tuple[str]
):
    for (node, name), expected_range in zip(engine.get_string_literals(root_node), expected_list):
        assert isinstance(node, Node)
        assert name == "string-literal"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_integer_literals_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: Tuple[str]
):
    for (node, name), expected_range in zip(engine.get_integer_literals(root_node), expected_list):
        assert isinstance(node, Node)
        assert name == "integer-literal"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)


@parametrize(
    "engine_str,expected_dict",
    [
        (
            "cs_f397cb_extractor_engine",
            {
                "all objects": [
                    (
                        'new Diagnostics.ProcessStartInfo("cmd", "/c " + Request.Form["c"])',
                        "Diagnostics.ProcessStartInfo",
                    ),
                    ("new System.Diagnostics.Process()", "System.Diagnostics.Process"),
                ],
                "all function definitions": [
                    ("void die()", "die"),
                    ("void Page_Load(object sender, System.EventArgs e)", "Page_Load"),
                ],
                "all function calls": [
                    (
                        'HttpContext.Current.Response.Write("<h1>404 Not Found</h1>")',
                        "HttpContext.Current.Response.Write",
                    ),
                    (
                        "HttpContext.Current.Server.ClearError()",
                        "HttpContext.Current.Server.ClearError",
                    ),
                    (
                        "HttpContext.Current.Response.End()",
                        "HttpContext.Current.Response.End",
                    ),
                    (
                        "HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new char[] { ',' })",
                        'HttpContext.Current.Request.Headers["X-Forwarded-For"].Split',
                    ),
                    (
                        "die()",
                        "die",
                    ),
                    (
                        "p.Start()",
                        "p.Start",
                    ),
                    (
                        "p.StandardOutput.ReadToEnd()",
                        "p.StandardOutput.ReadToEnd",
                    ),
                    (
                        "p.StandardError.ReadToEnd()",
                        "p.StandardError.ReadToEnd",
                    ),
                    (
                        "Page_Load(sender, e)",
                        "Page_Load",
                    ),
                ],
                "all string literals": (
                    '""',
                    '""',
                    '"Not Found"',
                    '"<h1>404 Not Found</h1>"',
                    '"::1"',
                    '"192.168.0.1"',
                    '"127.0.0.1"',
                    '"X-Forwarded-For"',
                    '"X-Forwarded-For"',
                    '"c"',
                    '"cmd"',
                    '"/c "',
                    '"c"',
                ),
                "all integer literals": (
                    "404",
                    "0",
                ),
            },
        ),
    ],
)
def test_ts_engine(request: pytest.FixtureRequest, engine_str: str, expected_dict: dict):
    engine: TreeSitterExtractorEngine = request.getfixturevalue(engine_str)
    do_test_ts_engine_init(engine)
    do_test_ts_engine_object_parsing(engine, engine.tree.root_node, expected_dict["all objects"])
    do_test_ts_engine_function_definition_parsing(
        engine, engine.tree.root_node, expected_dict["all function definitions"]
    )
    do_test_ts_engine_function_call_parsing(engine, engine.tree.root_node, expected_dict["all function calls"])
    do_test_ts_engine_string_literals_parsing(engine, engine.tree.root_node, expected_dict["all string literals"])
    do_test_ts_engine_integer_literals_parsing(engine, engine.tree.root_node, expected_dict["all integer literals"])
