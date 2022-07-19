from typing import List, Tuple

import pytest
import fixtures
from fixtures import *
from tree_sitter import Node, Tree

from capa.features.insn import API, Number, Property
from capa.features.common import (
    OS,
    OS_ANY,
    ARCH_ANY,
    FORMAT_SCRIPT,
    Arch,
    Format,
    String,
    Namespace,
    Substring,
    ScriptLanguage,
)
from capa.features.address import FileOffsetRangeAddress
from capa.features.extractors.script import LANG_CS, LANG_JS, LANG_TEM, LANG_HTML
from capa.features.extractors.ts.query import QueryBinding, HTMLQueryBinding, TemplateQueryBinding
from capa.features.extractors.ts.tools import LANGUAGE_TOOLKITS
from capa.features.extractors.ts.engine import (
    TreeSitterBaseEngine,
    TreeSitterHTMLEngine,
    TreeSitterTemplateEngine,
    TreeSitterExtractorEngine,
)


def do_test_ts_base_engine_init(engine: TreeSitterBaseEngine):
    assert engine.language in [LANG_CS, LANG_TEM, LANG_HTML, LANG_JS]
    assert isinstance(engine.query, QueryBinding)
    assert isinstance(engine.buf, bytes) and len(engine.buf) > 0
    assert isinstance(engine.tree, Tree)


def do_test_ts_base_engine_get_range(
    engine: TreeSitterBaseEngine, node: Node, expected_range: str, startswith: bool = False
):
    assert engine.get_range(node).startswith(expected_range) if startswith else engine.get_range(node) == expected_range


def do_test_ts_base_engine_get_address(engine: TreeSitterBaseEngine, node: Node):
    assert isinstance(engine.get_address(node), FileOffsetRangeAddress)
    addr = engine.get_address(node)
    assert addr.start_byte == node.start_byte and addr.end_byte == node.end_byte


def do_test_ts_base_engine_get_default_address(engine: TreeSitterBaseEngine):
    assert isinstance(engine.get_default_address(), FileOffsetRangeAddress)
    addr1 = engine.get_address(engine.tree.root_node)
    addr2 = engine.get_default_address()
    assert addr1.start_byte == addr2.start_byte and addr1.end_byte == addr2.end_byte


def do_test_ts_extractor_engine_init(engine: TreeSitterExtractorEngine, expected_language: str):
    assert engine.language == expected_language
    assert isinstance(engine.query, QueryBinding)
    assert isinstance(engine.get_default_address(), FileOffsetRangeAddress)
    assert isinstance(engine.buf_offset, int) and engine.buf_offset >= 0
    addr = engine.get_default_address()
    assert (
        addr.start_byte == engine.tree.root_node.start_byte + engine.buf_offset
        and addr.end_byte == engine.tree.root_node.end_byte + engine.buf_offset
    )


def do_test_ts_extractor_engine_get_address(
    engine: TreeSitterExtractorEngine, node: Node, expected_range: str, startswith: bool = False
):
    assert engine.get_range(node).startswith(expected_range) if startswith else engine.get_range(node) == expected_range


def do_test_ts_extractor_engine_get_new_objects(
    engine: TreeSitterExtractorEngine, root_node: Node, expected: List[Tuple[str, str]]
):
    assert len(list(engine.get_new_object_names(root_node))) == len(expected)
    for (node, name), (_, expected_name_range) in zip(engine.get_new_object_names(root_node), expected):
        assert isinstance(node, Node)
        assert name == "new-object"
        do_test_ts_base_engine_get_range(engine, node, expected_name_range)
        do_test_ts_base_engine_get_address(engine, node)


def do_test_ts_extractor_engine_get_function_definitions(
    engine: TreeSitterExtractorEngine, root_node: Node, expected: List[Tuple[str, str]]
):
    assert engine.get_function_definitions(engine.tree.root_node) == engine.get_function_definitions()
    assert len(engine.get_function_definitions(root_node)) == len(expected)
    for (node, name), (expected_range, expected_name_range) in zip(
        engine.get_function_definitions(root_node), expected
    ):
        assert isinstance(node, Node)
        assert name == "function-definition"
        do_test_ts_base_engine_get_range(engine, node, expected_range, startswith=True)
        do_test_ts_base_engine_get_address(engine, node)
        do_test_ts_base_engine_get_range(engine, engine.get_function_definition_name(node), expected_name_range)

    assert len(list(engine.get_function_definition_names(root_node))) == len(expected)
    for node, (_, expected_name_range) in zip(engine.get_function_definition_names(root_node), expected):
        assert isinstance(node, Node)
        do_test_ts_base_engine_get_range(engine, node, expected_name_range)
        do_test_ts_base_engine_get_address(engine, node)


def do_test_ts_extractor_engine_get_function_calls(
    engine: TreeSitterExtractorEngine, root_node: Node, expected: List[Tuple[str, str]]
):
    assert len(list(engine.get_function_call_names(root_node))) == len(expected)
    for (node, name), (_, expected_id_range) in zip(engine.get_function_call_names(root_node), expected):
        assert isinstance(node, Node)
        assert name == "function-call"
        do_test_ts_base_engine_get_range(engine, node, expected_id_range)
        do_test_ts_base_engine_get_address(engine, node)


def do_test_ts_extractor_engine_get_string_literals(
    engine: TreeSitterExtractorEngine, root_node: Node, expected: List[str]
):
    assert len(engine.get_string_literals(root_node)) == len(expected)
    for (node, name), expected_range in zip(engine.get_string_literals(root_node), expected):
        assert isinstance(node, Node)
        assert name == "string-literal"
        do_test_ts_base_engine_get_range(engine, node, expected_range)
        do_test_ts_base_engine_get_address(engine, node)


def do_test_ts_extractor_engine_get_integer_literals(
    engine: TreeSitterExtractorEngine, root_node: Node, expected: List[str]
):
    assert len(engine.get_integer_literals(root_node)) == len(expected)
    for (node, name), expected_range in zip(engine.get_integer_literals(root_node), expected):
        assert isinstance(node, Node)
        assert name == "integer-literal"
        do_test_ts_base_engine_get_range(engine, node, expected_range)
        do_test_ts_base_engine_get_address(engine, node)


def do_test_ts_extractor_engine_get_namespaces(engine: TreeSitterExtractorEngine, expected: List[str]):
    assert engine.get_namespaces(engine.tree.root_node) == engine.get_namespaces()
    assert len(engine.get_namespaces()) == len(expected)
    for (node, name), expected_range in zip(engine.get_namespaces(), expected):
        assert isinstance(node, Node)
        assert name == "namespace"
        do_test_ts_base_engine_get_range(engine, node, expected_range)
        do_test_ts_base_engine_get_address(engine, node)


def do_test_ts_extractor_engine_get_global_statements(engine: TreeSitterExtractorEngine, expected: List[str]):
    assert len(engine.get_global_statements()) == len(expected)
    for (node, name), expected_range in zip(engine.get_global_statements(), expected):
        assert isinstance(node, Node)
        assert name == "global-statement"
        do_test_ts_base_engine_get_range(engine, node, expected_range, startswith=True)
        do_test_ts_base_engine_get_address(engine, node)


def do_test_ts_extractor_engine_get_assigned_property_names(
    engine: TreeSitterExtractorEngine, root_node: Node, expected: List[str]
):
    assert len(list(engine.get_assigned_property_names(root_node))) == len(expected)
    for (node, name), expected_range in zip(engine.get_assigned_property_names(root_node), expected):
        assert isinstance(node, Node)
        assert name == "property"
        do_test_ts_base_engine_get_range(engine, node, expected_range, startswith=True)
        do_test_ts_base_engine_get_address(engine, node)


@parametrize(
    "engine_str,expected",
    [
        (
            "cs_138cdc_extractor_engine",
            {
                "language": LANG_CS,
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
                "properties": [
                    "HttpContext.Current.Response.StatusCode",
                    "HttpContext.Current.Response.StatusDescription",
                    "procStartInfo.RedirectStandardOutput",
                    "procStartInfo.RedirectStandardError",
                    "procStartInfo.UseShellExecute",
                    "procStartInfo.CreateNoWindow",
                    "p.StartInfo",
                ],
            },
        ),
    ],
)
def test_ts_extractor_engine(request: pytest.FixtureRequest, engine_str: str, expected: dict):
    engine: TreeSitterExtractorEngine = request.getfixturevalue(engine_str)
    do_test_ts_extractor_engine_init(engine, expected["language"])
    do_test_ts_extractor_engine_get_new_objects(engine, engine.tree.root_node, expected["all objects"])
    do_test_ts_extractor_engine_get_function_definitions(
        engine, engine.tree.root_node, expected["all function definitions"]
    )
    do_test_ts_extractor_engine_get_function_calls(engine, engine.tree.root_node, expected["all function calls"])
    do_test_ts_extractor_engine_get_string_literals(engine, engine.tree.root_node, expected["all string literals"])
    do_test_ts_extractor_engine_get_integer_literals(engine, engine.tree.root_node, expected["all integer literals"])
    do_test_ts_extractor_engine_get_assigned_property_names(engine, engine.tree.root_node, expected["properties"])
    do_test_ts_extractor_engine_get_global_statements(engine, expected["global statements"])
    do_test_ts_extractor_engine_get_namespaces(engine, expected["namespaces"])
    do_test_ts_base_engine_get_default_address(engine)


def do_test_ts_template_engine_init(engine: TreeSitterTemplateEngine):
    assert engine.language == LANG_TEM
    assert isinstance(engine.query, TemplateQueryBinding)
    assert isinstance(engine.buf, bytes) and len(engine.buf) > 0
    assert isinstance(engine.tree, Tree)
    assert isinstance(engine.get_default_address(), FileOffsetRangeAddress)
    addr = engine.get_default_address()
    assert addr.start_byte == engine.tree.root_node.start_byte and addr.end_byte == engine.tree.root_node.end_byte


def do_test_ts_template_engine_get_template_namespaces(
    engine: TreeSitterTemplateEngine, expected_language: str, expected: List[str]
):
    default_namespaces = LANGUAGE_TOOLKITS[expected_language].get_default_namespaces(True)
    template_namespaces = {name for _, name in engine.get_template_namespaces()}
    assert default_namespaces.issubset(template_namespaces)
    assert len(list(engine.get_imported_namespaces())) == len(expected)
    for (node, namespace), expected_namespace in zip(list(engine.get_imported_namespaces()), expected):
        assert isinstance(node, Node)
        assert engine.is_aspx_import_directive(node) == True
        assert engine.get_aspx_namespace(node) == expected_namespace
        assert namespace == expected_namespace


def do_test_ts_template_engine_get_code_sections(engine: TreeSitterTemplateEngine, expected: List[Tuple[int, int]]):
    assert len(engine.get_code_sections()) == len(expected)
    for (node, name), (expected_start_byte, expected_end_byte) in zip(list(engine.get_code_sections()), expected):
        assert isinstance(node, Node)
        assert name == "code"
        assert node.start_byte == expected_start_byte and node.end_byte == expected_end_byte


def do_test_ts_template_engine_get_content_sections(engine: TreeSitterTemplateEngine, expected: List[Tuple[int, int]]):
    assert len(engine.get_content_sections()) == len(expected)
    for (node, name), (expected_start_byte, expected_end_byte) in zip(list(engine.get_content_sections()), expected):
        assert isinstance(node, Node)
        assert name == "content"
        assert node.start_byte == expected_start_byte and node.end_byte == expected_end_byte


def do_test_ts_template_engine_get_parsed_code_sections(
    engine: TreeSitterTemplateEngine, expected_language: str, expected: List[Tuple[int, int]]
):
    assert len(list(engine.get_parsed_code_sections())) == len(expected)
    addrs = [e.get_default_address() for e in engine.get_parsed_code_sections()]
    for extractor_engine, (expected_start_byte, _) in zip(engine.get_parsed_code_sections(), expected):
        do_test_ts_extractor_engine_init(extractor_engine, expected_language)
        assert extractor_engine.buf_offset == expected_start_byte
        root = extractor_engine.tree.root_node
        addr = extractor_engine.get_default_address()
        assert (
            addr.start_byte == root.start_byte + expected_start_byte
            and addr.end_byte == root.end_byte + expected_start_byte
        )
        addr = extractor_engine.get_address(extractor_engine.tree.root_node)
        assert (
            addr.start_byte == root.start_byte + expected_start_byte
            and addr.end_byte == root.end_byte + expected_start_byte
        )


@parametrize(
    "engine_str,expected",
    [
        (
            "aspx_1f8f40_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Reflection"],
                "code sections": [(2, 23), (27, 64), (68, 469)],
                "content sections": [],
            },
        ),
        (
            "aspx_2b71dd_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Diagnostics", "System.IO"],
                "code sections": [(2, 50), (55, 95), (100, 131)],
                "content sections": [(52, 53), (97, 98), (133, 1273)],
            },
        ),
        (
            "aspx_2e8c7e_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Diagnostics", "System.IO"],
                "code sections": [(2, 23), (28, 67), (72, 103)],
                "content sections": [(25, 26), (69, 70), (105, 2919)],
            },
        ),
        (
            "aspx_03bb5c_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Web.UI.WebControls", "System.Diagnostics", "System.IO"],
                "code sections": [(2, 47), (53, 100), (106, 146), (152, 183), (1659, 7702)],
                "content sections": [(49, 51), (102, 104), (148, 150), (185, 1657), (7704, 10790)],
            },
        ),
        (
            "aspx_4f6fa6_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Diagnostics", "System.IO", "System.IO.Compression"],
                "code sections": [(2, 50), (55, 95), (100, 131), (136, 179), (186, 234)],
                "content sections": [(52, 53), (97, 98), (133, 134), (181, 183), (237, 6039)],
            },
        ),
        (
            "aspx_a35878_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": [
                    "System.IO",
                    "System.Diagnostics",
                    "System.Data",
                    "System.Management",
                    "System.Data.OleDb",
                    "Microsoft.Win32",
                    "System.Net.Sockets",
                    "System.Net",
                    "System.Web.UI",
                    "System.Runtime.InteropServices",
                    "System.DirectoryServices",
                    "System.ServiceProcess",
                    "System.Text.RegularExpressions",
                    "System.Threading",
                    "System.Data.SqlClient",
                    "Microsoft.VisualBasic",
                ],
                "code sections": [
                    (2, 123),
                    (128, 158),
                    (163, 202),
                    (207, 239),
                    (244, 282),
                    (287, 325),
                    (330, 366),
                    (371, 411),
                    (416, 448),
                    (453, 487),
                    (492, 543),
                    (548, 593),
                    (598, 640),
                    (645, 696),
                    (701, 738),
                    (743, 785),
                    (790, 832),
                    (837, 943),
                    (948, 1047),
                    (1052, 1155),
                    (1160, 1266),
                ],
                "content sections": [
                    (125, 126),
                    (160, 161),
                    (204, 205),
                    (241, 242),
                    (284, 285),
                    (327, 328),
                    (368, 369),
                    (413, 414),
                    (450, 451),
                    (489, 490),
                    (545, 546),
                    (595, 596),
                    (642, 643),
                    (698, 699),
                    (740, 741),
                    (787, 788),
                    (834, 835),
                    (945, 946),
                    (1049, 1050),
                    (1157, 1158),
                    (1268, 2680),
                ],
            },
        ),
        (
            "aspx_10162f_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.IO"],
                "code sections": [
                    (2, 71),
                    (76, 106),
                    (162, 2122),
                    (25579, 25596),
                    (25625, 25642),
                    (25664, 25700),
                    (25738, 25747),
                    (25801, 25822),
                    (25960, 25973),
                    (26002, 26015),
                    (26092, 26115),
                    (26153, 26168),
                    (26278, 26295),
                    (26324, 26341),
                    (26402, 26455),
                    (26472, 26489),
                    (26550, 26555),
                    (26593, 26612),
                    (26752, 26765),
                    (26794, 26811),
                    (26863, 26880),
                    (26941, 26946),
                    (26995, 27020),
                    (27037, 27062),
                    (27123, 27128),
                    (27166, 27181),
                    (27291, 27308),
                    (27337, 27354),
                    (27456, 27475),
                    (27686, 27711),
                    (27740, 27761),
                    (27854, 27879),
                    (27896, 27926),
                    (27992, 28002),
                    (28040, 28055),
                    (28167, 28188),
                    (28271, 28312),
                    (28374, 28443),
                    (28511, 28548),
                    (28610, 28675),
                    (28699, 28728),
                    (28789, 28794),
                    (28813, 28826),
                    (28871, 28876),
                    (28921, 28932),
                    (29044, 29077),
                    (29141, 29158),
                    (29220, 29226),
                    (29264, 29275),
                    (29359, 29384),
                    (29446, 29452),
                    (29490, 29501),
                    (29585, 29602),
                    (29664, 29670),
                    (29708, 29719),
                    (30163, 30170),
                ],
                "content sections": [
                    (73, 74),
                    (108, 160),
                    (2124, 25576),
                    (25598, 25622),
                    (25644, 25661),
                    (25702, 25735),
                    (25749, 25798),
                    (25824, 25957),
                    (25975, 25999),
                    (26017, 26089),
                    (26117, 26150),
                    (26170, 26275),
                    (26297, 26321),
                    (26343, 26399),
                    (26457, 26469),
                    (26491, 26547),
                    (26557, 26590),
                    (26614, 26749),
                    (26767, 26791),
                    (26813, 26860),
                    (26882, 26938),
                    (26948, 26992),
                    (27022, 27034),
                    (27064, 27120),
                    (27130, 27163),
                    (27183, 27288),
                    (27310, 27334),
                    (27356, 27453),
                    (27477, 27683),
                    (27713, 27737),
                    (27763, 27851),
                    (27881, 27893),
                    (27928, 27989),
                    (28004, 28037),
                    (28057, 28164),
                    (28190, 28268),
                    (28314, 28371),
                    (28445, 28508),
                    (28550, 28607),
                    (28677, 28696),
                    (28730, 28786),
                    (28796, 28810),
                    (28828, 28868),
                    (28878, 28918),
                    (28934, 29041),
                    (29079, 29138),
                    (29160, 29217),
                    (29228, 29261),
                    (29277, 29356),
                    (29386, 29443),
                    (29454, 29487),
                    (29503, 29582),
                    (29604, 29661),
                    (29672, 29705),
                    (29721, 30160),
                    (30172, 30635),
                ],
            },
        ),
        (
            "aspx_606dbf_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": [
                    "System",
                    "System.IO",
                    "System.Web",
                    "System.Web.SessionState",
                    "System.Web.UI",
                    "System.Web.Configuration",
                    "System.Threading",
                    "System.Net",
                    "System.Net.Sockets",
                    "System.Text",
                ],
                "code sections": [
                    (2, 87),
                    (93, 121),
                    (127, 158),
                    (164, 196),
                    (202, 247),
                    (253, 288),
                    (294, 340),
                    (346, 384),
                    (390, 422),
                    (428, 468),
                    (474, 507),
                ],
                "content sections": [
                    (89, 91),
                    (123, 125),
                    (160, 162),
                    (198, 200),
                    (249, 251),
                    (290, 292),
                    (342, 344),
                    (386, 388),
                    (424, 426),
                    (470, 472),
                    (509, 7078),
                ],
            },
        ),
        (
            "aspx_ea2a01_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Diagnostics", "System.IO", "System.Security.Cryptography", "System"],
                "code sections": [(2, 47), (53, 93), (99, 130), (136, 186), (192, 220), (228, 5811)],
                "content sections": [(49, 51), (95, 97), (132, 134), (188, 190), (222, 226), (5813, 5818)],
            },
        ),
        (
            "aspx_a5c893_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Reflection"],
                "code sections": [(2, 23), (27, 64), (68, 469)],
                "content sections": [(471, 472)],
            },
        ),
        (
            "aspx_b75f16_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.IO"],
                "code sections": [(2, 123), (127, 157), (303, 587)],
                "content sections": [(159, 301), (589, 596)],
            },
        ),
        (
            "aspx_d460ca_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": [
                    "System.Reflection",
                    "Microsoft.CSharp",
                    "System.CodeDom.Compiler",
                    "System.IO",
                    "System.Security.Cryptography",
                ],
                "code sections": [(2, 22), (27, 65), (70, 107), (112, 156), (161, 191), (196, 245)],
                "content sections": [(24, 25), (67, 68), (109, 110), (158, 159), (193, 194), (247, 4866)],
            },
        ),
        (
            "aspx_b4bb14_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Diagnostics", "System.IO"],
                "code sections": [(2, 50), (55, 95), (100, 131)],
                "content sections": [(52, 53), (97, 98), (133, 1398)],
            },
        ),
        (
            "aspx_f2bf20_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": [
                    "System.IO",
                    "System.IO.Compression",
                    "System.Diagnostics",
                    "System.Data",
                    "System.Data.OleDb",
                    "System.Data.Common",
                    "System.Data.SqlClient",
                    "System.Management",
                    "Microsoft.Win32",
                    "System.Net",
                    "System.Net.Sockets",
                    "System.Reflection",
                    "System.Runtime.InteropServices",
                    "System.DirectoryServices",
                    "System.ServiceProcess",
                    "System.Text.RegularExpressions",
                    "System.Security",
                    "System.Security.Permissions",
                    "System.Threading",
                ],
                "code sections": [
                    (2, 125),
                    (133, 164),
                    (170, 213),
                    (219, 259),
                    (265, 298),
                    (304, 343),
                    (349, 389),
                    (395, 438),
                    (444, 483),
                    (489, 526),
                    (532, 564),
                    (570, 610),
                    (616, 655),
                    (661, 713),
                    (719, 765),
                    (771, 814),
                    (820, 872),
                    (878, 915),
                    (921, 970),
                    (976, 1014),
                    (1020, 1127),
                    (1133, 1233),
                    (1239, 1343),
                    (39508, 39563),
                    (45103, 45113),
                    (47599, 47609),
                    (48705, 48712),
                ],
                "content sections": [
                    (127, 131),
                    (166, 168),
                    (215, 217),
                    (261, 263),
                    (300, 302),
                    (345, 347),
                    (391, 393),
                    (440, 442),
                    (485, 487),
                    (528, 530),
                    (566, 568),
                    (612, 614),
                    (657, 659),
                    (715, 717),
                    (767, 769),
                    (816, 818),
                    (874, 876),
                    (917, 919),
                    (972, 974),
                    (1016, 1018),
                    (1129, 1131),
                    (1235, 1237),
                    (1345, 39505),
                    (39565, 45100),
                    (45116, 47596),
                    (47612, 48702),
                    (48715, 55896),
                ],
            },
        ),
        (
            "aspx_5f959f_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Diagnostics", "System.IO"],
                "code sections": [(2, 50), (55, 95), (100, 131)],
                "content sections": [(52, 53), (97, 98), (133, 1400)],
            },
        ),
        (
            "aspx_f39dc0_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Diagnostics", "System.IO", "System.Net"],
                "code sections": [(2, 50), (56, 96), (102, 133), (139, 171), (678, 1421)],
                "content sections": [(52, 54), (98, 100), (135, 137), (173, 676), (1423, 1441)],
            },
        ),
        (
            "aspx_54433d_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": [
                    "System.Diagnostics",
                    "System.IO",
                    "System.IO.Compression",
                    "Microsoft.VisualBasic",
                ],
                "code sections": [(2, 50), (55, 95), (100, 131), (136, 179), (184, 227), (233, 280)],
                "content sections": [(52, 53), (97, 98), (133, 134), (181, 182), (229, 230), (283, 10444)],
            },
        ),
        (
            "aspx_f397cb_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System"],
                "code sections": [(2, 22), (28, 56), (3950, 3981), (4033, 4064)],
                "content sections": [(24, 26), (58, 3948), (3983, 4031), (4066, 4388)],
            },
        ),
        (
            "aspx_15eed4_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": [
                    "System.IO",
                    "System.Diagnostics",
                    "System.Data",
                    "System.Management",
                    "System.Data.OleDb",
                    "Microsoft.Win32",
                    "System.Net.Sockets",
                    "System.Net",
                    "System.Runtime.InteropServices",
                    "System.DirectoryServices",
                    "System.ServiceProcess",
                    "System.Text.RegularExpressions",
                    "System.Threading",
                    "System.Data.SqlClient",
                    "Microsoft.VisualBasic",
                ],
                "code sections": [
                    (2, 123),
                    (128, 158),
                    (163, 202),
                    (207, 239),
                    (244, 282),
                    (287, 325),
                    (330, 366),
                    (371, 411),
                    (416, 448),
                    (453, 504),
                    (509, 554),
                    (559, 601),
                    (606, 657),
                    (662, 699),
                    (704, 746),
                    (751, 793),
                    (798, 904),
                    (909, 1008),
                    (1013, 1116),
                    (1121, 1227),
                    (54081, 54091),
                    (55610, 55620),
                    (56304, 56315),
                    (57500, 57508),
                    (57995, 58004),
                    (58531, 58541),
                    (58984, 58994),
                    (59512, 59521),
                    (60014, 60024),
                    (60284, 60291),
                    (61559, 61564),
                    (62217, 62227),
                    (62711, 62721),
                    (66897, 66906),
                    (67954, 67962),
                ],
                "content sections": [
                    (125, 126),
                    (160, 161),
                    (204, 205),
                    (241, 242),
                    (284, 285),
                    (327, 328),
                    (368, 369),
                    (413, 414),
                    (450, 451),
                    (506, 507),
                    (556, 557),
                    (603, 604),
                    (659, 660),
                    (701, 702),
                    (748, 749),
                    (795, 796),
                    (906, 907),
                    (1010, 1011),
                    (1118, 1119),
                    (1229, 54078),
                    (54094, 55607),
                    (55623, 56301),
                    (56318, 57497),
                    (57511, 57992),
                    (58007, 58528),
                    (58544, 58981),
                    (58997, 59509),
                    (59524, 60011),
                    (60027, 60281),
                    (60294, 61556),
                    (61567, 62214),
                    (62230, 62708),
                    (62724, 66894),
                    (66909, 67951),
                    (67965, 70053),
                ],
            },
        ),
        (
            "aspx_6f3261_template_engine",
            {
                "language": LANG_CS,
                "aspx namespaces": ["System.Data", "System.Data.SqlClient"],
                "code sections": [(2, 23), (28, 60), (65, 107)],
                "content sections": [(25, 26), (62, 63), (109, 3303)],
            },
        ),
    ],
)
def test_ts_template_engine(request: pytest.FixtureRequest, engine_str: str, expected: dict):
    engine: TreeSitterTemplateEngine = request.getfixturevalue(engine_str)
    do_test_ts_template_engine_init(engine)
    assert engine.identify_language() == expected["language"]
    do_test_ts_template_engine_get_template_namespaces(engine, expected["language"], expected["aspx namespaces"])
    do_test_ts_template_engine_get_code_sections(engine, expected["code sections"])
    do_test_ts_template_engine_get_parsed_code_sections(engine, expected["language"], expected["code sections"])
    do_test_ts_template_engine_get_content_sections(engine, expected["content sections"])
    for expected_start_byte, expected_end_byte in expected["content sections"]:
        template_namespaces = list(engine.get_template_namespaces())
        additional_namespaces = set(name for _, name in template_namespaces)
        html_engine = TreeSitterHTMLEngine(engine.buf[expected_start_byte:expected_end_byte], additional_namespaces)
        do_test_ts_html_engine_init(html_engine)


def do_test_ts_html_engine_init(engine: TreeSitterHTMLEngine):
    assert engine.language == LANG_HTML
    assert isinstance(engine.query, HTMLQueryBinding)
    assert isinstance(engine.buf, bytes) and len(engine.buf) > 0
    assert isinstance(engine.tree, Tree)
    assert isinstance(engine.get_default_address(), FileOffsetRangeAddress)
    assert isinstance(engine.namespaces, set)
    addr = engine.get_default_address()
    assert addr.start_byte == engine.tree.root_node.start_byte and addr.end_byte == engine.tree.root_node.end_byte


FEATURE_PRESENCE_TESTS_SCRIPTS = sorted(
    [
        ("cs_138cdc", "global", Arch(ARCH_ANY), True),
        ("cs_138cdc", "global", OS(OS_ANY), True),
        ("cs_138cdc", "file", Format(FORMAT_SCRIPT), True),
        ("cs_138cdc", "file", ScriptLanguage(LANG_CS), True),
        ("cs_138cdc", "file", Namespace("System"), True),
        ("cs_138cdc", "function=PSEUDO MAIN", String(""), True),
        ("cs_138cdc", "function=die", String("Not Found"), True),
        ("cs_138cdc", "function=Page_Load", String("127.0.0.1"), True),
        ("cs_138cdc", "function=Page_Load", API("System.Diagnostics.ProcessStartInfo"), True),
        ("cs_138cdc", "function=Page_Load", API("System.Diagnostics.Process"), True),
        (
            "cs_138cdc",
            "function=Page_Load",
            Property("System.Diagnostics.ProcessStartInfo::RedirectStandardOutput"),
            True,
        ),
        ("aspx_4f6fa6", "global", Arch(ARCH_ANY), True),
        ("aspx_4f6fa6", "global", OS(OS_ANY), True),
        ("aspx_4f6fa6", "file", Format(FORMAT_SCRIPT), True),
        ("aspx_4f6fa6", "file", ScriptLanguage(LANG_CS), True),
        ("aspx_4f6fa6", "file", Namespace("System.Diagnostics"), True),
        ("aspx_4f6fa6", "file", Namespace("System.IO"), True),
        ("aspx_4f6fa6", "file", Namespace("System.IO.Compression"), True),
        ("aspx_4f6fa6", "function=do_ps", String("powershell.exe"), True),
        ("aspx_4f6fa6", "function=do_ps", Substring("-executionpolicy bypass"), True),
        ("aspx_4f6fa6", "function=do_ps", API("System.Diagnostics.ProcessStartInfo"), True),
        ("aspx_4f6fa6", "function=do_ps", API("System.Diagnostics.Process::Start"), True),
        ("aspx_4f6fa6", "function=ps", String("\\nPS> "), True),
        ("aspx_4f6fa6", "function=ps", Substring("PS>"), True),
        ("aspx_4f6fa6", "function=downloadbutton_Click", Substring("filename"), True),
        ("aspx_4f6fa6", "function=base64encode", API("System.Convert::ToBase64String"), True),
        ("aspx_5f959f", "global", Arch(ARCH_ANY), True),
        ("aspx_5f959f", "global", OS(OS_ANY), True),
        ("aspx_5f959f", "file", Format(FORMAT_SCRIPT), True),
        ("aspx_5f959f", "file", ScriptLanguage(LANG_CS), True),
        ("aspx_5f959f", "file", Namespace("System.Diagnostics"), True),
        ("aspx_5f959f", "file", Namespace("System.IO"), True),
        ("aspx_5f959f", "file", Namespace("System.Web.SessionState"), True),
        ("aspx_5f959f", "function=ExcuteCmd", API("System.Diagnostics.ProcessStartInfo"), True),
        ("aspx_5f959f", "function=ExcuteCmd", String("cmd.exe"), True),
        ("aspx_5f959f", "function=ExcuteCmd", Substring("/c"), True),
        ("aspx_5f959f", "function=ExcuteCmd", API("System.Diagnostics.Process::Start"), True),
        ("aspx_5f959f", "function=ExcuteCmd", Property("System.Diagnostics.ProcessStartInfo::FileName"), True),
        ("aspx_5f959f", "function=ExcuteCmd", Property("System.Diagnostics.ProcessStartInfo::Arguments"), True),
        ("aspx_5f959f", "function=ExcuteCmd", Property("System.Diagnostics.ProcessStartInfo::UseShellExecute"), True),
        (
            "aspx_5f959f",
            "function=ExcuteCmd",
            Property("System.Diagnostics.ProcessStartInfo::RedirectStandardOutput"),
            True,
        ),
        ("aspx_5f959f", "function=cmdExe_Click", String("<pre>"), True),
        ("aspx_5f959f", "function=cmdExe_Click", String("</pre>"), True),
        ("aspx_10162f", "global", Arch(ARCH_ANY), True),
        ("aspx_10162f", "global", OS(OS_ANY), True),
        ("aspx_10162f", "file", Format(FORMAT_SCRIPT), True),
        ("aspx_10162f", "file", ScriptLanguage(LANG_CS), True),
        ("aspx_10162f", "file", Namespace("System.IO"), True),
        ("aspx_10162f", "file", Namespace("System.Web.Security"), True),
        ("aspx_10162f", "function=PSEUDO MAIN", String("data"), True),
        ("aspx_10162f", "function=PSEUDO MAIN", String("gsize"), True),
        ("aspx_10162f", "function=PSEUDO MAIN", String("cmd"), True),
        ("aspx_10162f", "function=PSEUDO MAIN", String("ttar"), True),
        ("aspx_10162f", "function=PSEUDO MAIN", String("sdfewq@#$51234234DF@#$!@#$ASDF"), True),
        ("aspx_10162f", "function=rm", API("System.IO.File::Delete"), False),
        ("aspx_10162f", "function=(0x564, 0x6af)", API("System.Convert::ToBase64String"), True),
        ("aspx_10162f", "function=(0x564, 0x6af)", API("System.Convert::ToBase64String"), True),
        ("aspx_10162f", "function=(0x564, 0x6af)", String("p"), True),
        (
            "aspx_10162f",
            "function=c",
            API("System.Security.Cryptography.SHA256CryptoServiceProvider::ComputeHash"),
            True,
        ),
        ("aspx_10162f", "function=z", API("System.IO.File::ReadAllBytes"), True),
        ("aspx_10162f", "function=ti", API("System.IO.File::GetCreationTime"), True),
        ("aspx_10162f", "function=ti", API("System.IO.File::GetLastAccessTime"), True),
        ("aspx_10162f", "function=ti", API("System.IO.File::GetCreationTime"), True),
        ("aspx_10162f", "function=g", API("System.IO.File::GetLastAccessTime"), True),
        ("aspx_10162f", "function=g", API("System.IO.File::GetLastWriteTime"), True),
        ("aspx_10162f", "function=g", API("System.IO.File::GetLastWriteTime"), True),
        ("aspx_10162f", "function=g", API("System.IO.File::SetCreationTime"), True),
        ("aspx_10162f", "function=g", API("System.IO.File::SetLastAccessTime"), True),
        ("aspx_10162f", "function=g", API("System.IO.File::SetLastWriteTime"), True),
        ("aspx_10162f", "function=h", API("System.IO.Path::GetTempPath"), True),
        ("aspx_10162f", "function=h", API("System.IO.File::WriteAllBytes"), True),
        ("aspx_10162f", "function=h", API("System.Convert::FromBase64String"), True),
        ("aspx_10162f", "function=d", API("System.IO.File::Delete"), True),
        ("aspx_10162f", "function=d", API("System.IO.File::Delete"), True),
        ("aspx_10162f", "function=sq", API("System.Data.SqlClient.SqlConnection"), True),
        ("aspx_10162f", "function=sq", API("System.Data.SqlClient.SqlConnection"), True),
        ("aspx_10162f", "function=sq", API("System.Data.SqlClient.SqlCommand"), True),
        ("aspx_10162f", "function=sq", API("System.Data.SqlClient.SqlDataAdapter"), True),
        ("aspx_10162f", "function=sq", API("System.Data.SqlClient.SqlConnection::Open"), True),
        ("aspx_10162f", "function=exec", API("System.Diagnostics.Process"), True),
        ("aspx_10162f", "function=exec", String("cmd.exe"), True),
        ("aspx_10162f", "function=exec", Property("System.Diagnostics.Process.StartInfo::FileName"), True),
        ("aspx_10162f", "function=exec", Property("System.Diagnostics.Process.StartInfo::UseShellExecute"), True),
        ("aspx_10162f", "function=exec", Property("System.Diagnostics.Process.StartInfo::RedirectStandardInput"), True),
        (
            "aspx_10162f",
            "function=exec",
            Property("System.Diagnostics.Process.StartInfo::RedirectStandardOutput"),
            True,
        ),
        ("aspx_10162f", "function=exec", Property("System.Diagnostics.Process.StartInfo::CreateNoWindow"), True),
        ("aspx_10162f", "function=gsize", Substring("error"), True),
        ("aspx_10162f", "function=exp", Substring("root"), True),
        ("aspx_10162f", "function=exp", Substring("net use"), True),
        ("aspx_10162f", "function=exp", Number(2), True),
        ("aspx_10162f", "function=exp", API("System.IO.DirectoryInfo"), True),
        ("aspx_10162f", "function=exp", API("System.IO.File::GetAttributes"), True),
        ("aspx_10162f", "function=GetDirSize", Number(0), True),
        ("aspx_10162f", "function=createJsonDirectory", String('\\"dir\\":['), True),
        ("aspx_10162f", "function=createJsonDirectory", Number(0), True),
        ("aspx_10162f", "function=createJsonFile", Substring("file"), True),
        ("aspx_10162f", "function=sizeFix", Number(1024), True),
        ("aspx_10162f", "function=sizeFix", Number(2), True),
        ("aspx_10162f", "function=sizeFix", Substring("GB"), True),
        ("aspx_2b71dd", "global", Arch(ARCH_ANY), True),
        ("aspx_f2bf20", "global", Arch(ARCH_ANY), True),
        ("aspx_f39dc0", "global", Arch(ARCH_ANY), True),
        ("aspx_ea2a01", "global", Arch(ARCH_ANY), True),
        ("aspx_6f3261", "global", Arch(ARCH_ANY), True),
        ("aspx_1f8f40", "global", Arch(ARCH_ANY), True),
        ("aspx_2e8c7e", "global", Arch(ARCH_ANY), True),
        ("aspx_03bb5c", "global", Arch(ARCH_ANY), True),
        ("aspx_606dbf", "global", Arch(ARCH_ANY), True),
        ("aspx_f397cb", "global", Arch(ARCH_ANY), True),
        ("aspx_b4bb14", "global", Arch(ARCH_ANY), True),
        ("aspx_54433d", "global", Arch(ARCH_ANY), True),
        ("aspx_a35878", "global", Arch(ARCH_ANY), True),
        ("aspx_a5c893", "global", Arch(ARCH_ANY), True),
        ("aspx_15eed4", "global", Arch(ARCH_ANY), True),
        ("aspx_b75f16", "global", Arch(ARCH_ANY), True),
        ("aspx_d460ca", "global", Arch(ARCH_ANY), True),
    ]
)


@parametrize(
    "sample_ts, scope_ts, feature, expected", FEATURE_PRESENCE_TESTS_SCRIPTS, indirect=["sample_ts", "scope_ts"]
)
def test_ts_extractor(sample_ts, scope_ts, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_ts_extractor, sample_ts, scope_ts, feature, expected)
