from __future__ import annotations

from io import StringIO

from rich.text import Text
from rich.theme import Theme
from rich.console import Console

from mapa.model import MapaFunction, MapaMeta, MapaReport, MapaString
from mapa.renderer import Renderer, _render_string_line, _visible_tags, render_report
from mapa.string_tags.model import StringTagMatch, StringTagResult
from mapa.string_tags.loaders import (
    load_expert_database,
    load_gp_hash_databases,
    load_gp_jsonl_databases,
    load_junk_code_database,
    load_oss_databases,
    load_winapi_database,
)
from mapa.string_tags.tagger import StringTagger, load_default_tagger


class TestOssLoader:
    def test_zlib_string(self):
        dbs = load_oss_databases()
        found = False
        for db in dbs:
            hit = db.query("invalid distance code")
            if hit is not None:
                assert hit.library_name == "zlib"
                found = True
                break
        assert found

    def test_msvc_string(self):
        dbs = load_oss_databases()
        found = False
        for db in dbs:
            hit = db.query("IsolationAware function called after IsolationAwareCleanup")
            if hit is not None:
                assert hit.library_name == "msvc"
                found = True
                break
        assert found

    def test_miss(self):
        dbs = load_oss_databases()
        for db in dbs:
            assert db.query("this string does not exist in any library") is None


class TestExpertLoader:
    def test_exact_match(self):
        db = load_expert_database()
        hits = db.query("CurrencyDispenser1")
        assert any(r.tag == "#capa" for r in hits)

    def test_substring_match(self):
        db = load_expert_database()
        hits = db.query("something with CurrencyDispenser1 in it")
        tags = {r.tag for r in hits}
        assert "#capa" in tags or len(hits) == 0

    def test_miss(self):
        db = load_expert_database()
        hits = db.query("completely unrelated string xyz123")
        assert len(hits) == 0


class TestWinapiLoader:
    def test_dll_case_insensitive(self):
        db = load_winapi_database()
        assert db.query("kernel32.dll")
        assert db.query("KERNEL32.DLL")
        assert db.query("Kernel32.dll")

    def test_api_exact(self):
        db = load_winapi_database()
        assert db.query("CreateFileA")

    def test_miss(self):
        db = load_winapi_database()
        assert not db.query("NotARealApiFunction12345")


class TestGpJsonlLoader:
    def test_common_string(self):
        dbs = load_gp_jsonl_databases()
        found = False
        for db in dbs:
            if db.query("!This program cannot be run in DOS mode."):
                found = True
                break
        assert found

    def test_miss(self):
        dbs = load_gp_jsonl_databases()
        for db in dbs:
            assert db.query("xyzzy_not_a_real_string_99999") is None


class TestGpHashLoader:
    def test_loads(self):
        dbs = load_gp_hash_databases()
        assert len(dbs) == 2
        for db in dbs:
            assert len(db.hashes) > 0


class TestJunkCodeLoader:
    def test_initterm(self):
        db = load_junk_code_database()
        assert db.query("_initterm") is not None


class TestTagger:
    def test_zlib_tag(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("invalid distance code")
        assert "#zlib" in result.tags

    def test_capa_tag(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("CurrencyDispenser1")
        assert "#capa" in result.tags

    def test_winapi_tag(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("CreateFileA")
        assert "#winapi" in result.tags

    def test_common_tag(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("!This program cannot be run in DOS mode.")
        assert "#common" in result.tags

    def test_code_junk_tag(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("_initterm")
        assert "#code-junk" in result.tags

    def test_multi_tag(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("_initterm")
        assert "#winapi" in result.tags or "#code-junk" in result.tags

    def test_empty_string(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("")
        assert result.tags == ()

    def test_no_match(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("xyzzy_unique_test_string_42")
        assert result.tags == ()
        assert result.matches == ()

    def test_tags_sorted(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("_initterm")
        assert result.tags == tuple(sorted(result.tags))

    def test_metadata_preserved_for_multiple_common_sources(self):
        tagger = load_default_tagger()
        result = tagger.tag_string("!This program cannot be run in DOS mode.")
        common_matches = [m for m in result.matches if m.tag == "#common"]
        assert len(common_matches) >= 1


class TestVisibleTags:
    def test_common_only(self):
        assert _visible_tags(("#common",)) == ["#common"]

    def test_common_with_specific(self):
        assert _visible_tags(("#common", "#winapi")) == ["#winapi"]

    def test_code_junk_kept_with_others(self):
        tags = ("#code-junk", "#winapi")
        visible = _visible_tags(tags)
        assert "#code-junk" in visible
        assert "#winapi" in visible

    def test_empty(self):
        assert _visible_tags(()) == []


def _make_console(width: int = 120) -> tuple[Console, StringIO]:
    buf = StringIO()
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
    console = Console(
        theme=theme,
        markup=False,
        emoji=False,
        file=buf,
        force_terminal=False,
        width=width,
        no_color=True,
    )
    return console, buf


class TestStringLineRenderer:
    def test_untagged_matches_old_format(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="main",
                    strings=[MapaString(value="Hello World", address=0x4000)],
                ),
            ],
        )
        console, buf = _make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert 'string:' in output
        assert "Hello World" in output

    def test_tagged_string_shows_tag_at_right(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="main",
                    strings=[MapaString(value="invalid distance code", address=0x4000, tags=("#zlib",))],
                ),
            ],
        )
        console, buf = _make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "#zlib" in output
        assert "invalid distance code" in output

    def test_tag_alignment_right_edge(self):
        console, _ = _make_console(width=80)
        o = Renderer(console)
        line = _render_string_line(o, "test string", ["#zlib"])
        assert line.plain.rstrip().endswith("#zlib")

    def test_narrow_terminal_still_shows_tags(self):
        console, _ = _make_console(width=30)
        o = Renderer(console)
        line = _render_string_line(o, "a very long string value here that exceeds width", ["#zlib"])
        assert "#zlib" in line.plain

    def test_common_hidden_when_specific_present(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="main",
                    strings=[
                        MapaString(
                            value="CreateFileA",
                            address=0x4000,
                            tags=("#common", "#winapi"),
                        )
                    ],
                ),
            ],
        )
        console, buf = _make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "#winapi" in output
        assert "#common" not in output

    def test_common_shown_when_only_tag(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="main",
                    strings=[
                        MapaString(
                            value="!This program cannot be run in DOS mode.",
                            address=0x4000,
                            tags=("#common",),
                        )
                    ],
                ),
            ],
        )
        console, buf = _make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "#common" in output


class TestReportModel:
    def test_string_with_library_tag(self):
        ms = MapaString(
            value="invalid distance code",
            address=0x1000,
            tags=("#zlib",),
            tag_matches=(
                StringTagMatch(
                    tag="#zlib",
                    source_family="oss",
                    source_name="zlib",
                    library_name="zlib",
                    library_version="1.3.1",
                ),
            ),
        )
        assert ms.tags == ("#zlib",)
        assert ms.tag_matches[0].library_name == "zlib"

    def test_string_with_multi_tag(self):
        ms = MapaString(
            value="_initterm",
            address=0x2000,
            tags=("#code-junk", "#winapi"),
            tag_matches=(
                StringTagMatch(tag="#code-junk", source_family="gp", source_name="junk-code"),
                StringTagMatch(tag="#winapi", source_family="winapi", source_name="winapi"),
            ),
        )
        assert "#code-junk" in ms.tags
        assert "#winapi" in ms.tags
        assert len(ms.tag_matches) == 2

    def test_string_with_common_tag(self):
        ms = MapaString(
            value="!This program cannot be run in DOS mode.",
            address=0x3000,
            tags=("#common",),
        )
        assert ms.tags == ("#common",)

    def test_report_with_tagged_strings(self):
        report = MapaReport(
            meta=MapaMeta(name="test.exe", sha256="abc"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="main",
                    strings=[
                        MapaString(value="invalid distance code", address=0x2000, tags=("#zlib",)),
                        MapaString(value="CreateFileA", address=0x3000, tags=("#common", "#winapi")),
                        MapaString(value="_initterm", address=0x4000, tags=("#code-junk", "#winapi")),
                    ],
                ),
            ],
        )
        assert len(report.functions[0].strings) == 3
        all_tags = set()
        for s in report.functions[0].strings:
            all_tags.update(s.tags)
        assert "#zlib" in all_tags
        assert "#winapi" in all_tags
        assert "#code-junk" in all_tags
        assert "#common" in all_tags
