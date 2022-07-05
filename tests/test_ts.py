from typing import List, Tuple

import pytest
import fixtures
from fixtures import *
from tree_sitter import Node, Tree

from capa.features.file import Import
from capa.features.common import OS, OS_ANY, ARCH_ANY, FORMAT_SCRIPT, Arch, Format, String, Namespace, ScriptLanguage
from capa.features.address import NO_ADDRESS, FileOffsetRangeAddress
from capa.features.extractors.script import LANG_CS
from capa.features.extractors.ts.query import QueryBinding
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine


def do_test_ts_engine_init(engine: TreeSitterExtractorEngine):
    assert engine.language == LANG_CS
    assert isinstance(engine.query, QueryBinding)
    assert isinstance(engine.import_signatures, set) and len(engine.import_signatures) > 0
    assert isinstance(engine.path, str) and len(engine.path) > 0
    assert isinstance(engine.buf, bytes) and len(engine.buf) > 0
    assert isinstance(engine.tree, Tree)
    assert isinstance(engine.get_default_address(), FileOffsetRangeAddress)
    addr = engine.get_default_address()
    assert addr.start_byte == engine.tree.root_node.start_byte and addr.end_byte == engine.tree.root_node.end_byte


def do_test_range(engine: TreeSitterExtractorEngine, node: Node, expected_range: str, startswith: bool = False):
    assert engine.get_range(node).startswith(expected_range) if startswith else engine.get_range(node) == expected_range


def do_test_range_address(engine: TreeSitterExtractorEngine, node: Node):
    assert isinstance(engine.get_address(node), FileOffsetRangeAddress)
    addr = engine.get_address(node)
    assert addr.start_byte == node.start_byte and addr.end_byte == node.end_byte


def do_test_ts_engine_default_range_address(engine: TreeSitterExtractorEngine):
    assert isinstance(engine.get_default_address(), FileOffsetRangeAddress)
    addr1 = engine.get_address(engine.tree.root_node)
    addr2 = engine.get_default_address()
    assert addr1.start_byte == addr2.start_byte and addr1.end_byte == addr2.end_byte


def do_test_ts_engine_object_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[Tuple[str, str]]
):
    assert len(engine.get_new_objects(root_node)) == len(expected_list)
    for (node, name), (expected_range, expected_id_range) in zip(engine.get_new_objects(root_node), expected_list):
        assert isinstance(node, Node)
        assert name == "object.new"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)
        do_test_range(engine, engine.get_object_id(node), expected_id_range)

    assert len(list(engine.get_new_object_ids(root_node))) == len(expected_list)
    for node, (_, expected_id_range) in zip(engine.get_new_object_ids(root_node), expected_list):
        assert isinstance(node, Node)
        do_test_range(engine, node, expected_id_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_function_definition_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[Tuple[str, str]]
):
    assert engine.get_function_definitions(engine.tree.root_node) == engine.get_function_definitions()
    assert len(engine.get_function_definitions(root_node)) == len(expected_list)
    for (node, name), (expected_range, expected_id_range) in zip(
        engine.get_function_definitions(root_node), expected_list
    ):
        assert isinstance(node, Node)
        assert name == "function.definition"
        do_test_range(engine, node, expected_range, startswith=True)
        do_test_range_address(engine, node)
        do_test_range(engine, engine.get_function_definition_id(node), expected_id_range)

    assert len(list(engine.get_function_definition_ids(root_node))) == len(expected_list)
    for node, (_, expected_id_range) in zip(engine.get_function_definition_ids(root_node), expected_list):
        assert isinstance(node, Node)
        do_test_range(engine, node, expected_id_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_function_call_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[Tuple[str, str]]
):
    assert len(engine.get_function_calls(root_node)) == len(expected_list)
    for (node, name), (expected_range, expected_id_range) in zip(engine.get_function_calls(root_node), expected_list):
        assert isinstance(node, Node)
        assert name == "function.call"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)
        do_test_range(engine, engine.get_function_call_id(node), expected_id_range)

    assert len(list(engine.get_function_call_ids(root_node))) == len(expected_list)
    for node, (_, expected_id_range) in zip(engine.get_function_call_ids(root_node), expected_list):
        assert isinstance(node, Node)
        do_test_range(engine, node, expected_id_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_string_literals_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[str]
):
    assert len(engine.get_string_literals(root_node)) == len(expected_list)
    for (node, name), expected_range in zip(engine.get_string_literals(root_node), expected_list):
        assert isinstance(node, Node)
        assert name == "string-literal"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_integer_literals_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[str]
):
    assert len(engine.get_integer_literals(root_node)) == len(expected_list)
    for (node, name), expected_range in zip(engine.get_integer_literals(root_node), expected_list):
        assert isinstance(node, Node)
        assert name == "integer-literal"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_namespaces_parsing(engine: TreeSitterExtractorEngine, expected_list: List[str]):
    assert engine.get_namespaces(engine.tree.root_node) == engine.get_namespaces()
    assert len(engine.get_namespaces()) == len(expected_list)
    for (node, name), expected_range in zip(engine.get_namespaces(), expected_list):
        assert isinstance(node, Node)
        assert name == "namespace"
        do_test_range(engine, node, expected_range)
        do_test_range_address(engine, node)


def do_test_ts_engine_global_statements_parsing(engine: TreeSitterExtractorEngine, expected_list: List[str]):
    assert len(engine.get_global_statements()) == len(expected_list)
    for (node, name), expected_range in zip(engine.get_global_statements(), expected_list):
        assert isinstance(node, Node)
        assert name == "global-statement"
        do_test_range(engine, node, expected_range, startswith=True)
        do_test_range_address(engine, node)


def do_test_ts_engine_import_names_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[str]
):
    assert len(list(engine.get_import_names(root_node))) == len(expected_list)
    for (node, import_name), expected_import_name in zip(list(engine.get_import_names(root_node)), expected_list):
        assert isinstance(node, Node)
        assert import_name == expected_import_name
        do_test_range_address(engine, node)


def do_test_ts_engine_function_names_parsing(
    engine: TreeSitterExtractorEngine, root_node: Node, expected_list: List[str]
):
    assert len(list(engine.get_function_names(root_node))) == len(expected_list)
    for (node, function_name), expected_function_name in zip(list(engine.get_function_names(root_node)), expected_list):
        assert isinstance(node, Node)
        assert function_name == expected_function_name
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
                ],
                "all string literals": [
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
                ],
                "all integer literals": [
                    "404",
                    "0",
                ],
                "namespaces": ["System"],
                "global statements": [
                    'string stdout = "";',
                    'string stderr = "";',
                ],
                "all import names": ["System.Diagnostics.ProcessStartInfo", "System.Diagnostics.Process"],
                "all function names": [],
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
    do_test_ts_engine_import_names_parsing(engine, engine.tree.root_node, expected_dict["all import names"])
    do_test_ts_engine_function_names_parsing(engine, engine.tree.root_node, expected_dict["all function names"])
    do_test_ts_engine_global_statements_parsing(engine, expected_dict["global statements"])
    do_test_ts_engine_namespaces_parsing(engine, expected_dict["namespaces"])
    do_test_ts_engine_default_range_address(engine)


FEATURE_PRESENCE_TESTS_SCRIPTS = sorted(
    [
        ("cs_f397cb", "global", Arch(ARCH_ANY), True),
        ("cs_f397cb", "global", OS(OS_ANY), True),
        ("cs_f397cb", "file", Format(FORMAT_SCRIPT), True),
        ("cs_f397cb", "file", ScriptLanguage(LANG_CS), True),
        ("cs_f397cb", "file", Namespace("System"), True),
        ("cs_f397cb", "file", String(""), True),
        ("cs_f397cb", "function=(0x38,0x16c)", String("Not Found"), True),
        ("cs_f397cb", "function=(0x16e,0x7ce)", String("127.0.0.1"), True),
        ("cs_f397cb", "function=(0x16e,0x7ce)", Import("System.Diagnostics.ProcessStartInfo"), True),
        ("cs_f397cb", "function=(0x16e,0x7ce)", Import("System.Diagnostics.Process"), True),
    ]
)


@parametrize("sample, scope_ts, feature, expected", FEATURE_PRESENCE_TESTS_SCRIPTS, indirect=["sample", "scope_ts"])
def test_ts_extractor(sample, scope_ts, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_ts_extractor, sample, scope_ts, feature, expected)
