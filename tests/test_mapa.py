from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console
from rich.theme import Theme

from mapa.assemblage import load_assemblage_records
from mapa.cli import (
    build_parser,
    open_html_report,
    validate_output_options,
    write_temp_html_report,
)
from mapa.html_renderer import render_html_map
from mapa.model import (
    AssemblageRecord,
    MapaCall,
    MapaCaller,
    MapaFunction,
    MapaLibrary,
    MapaMeta,
    MapaProgramString,
    MapaReport,
    MapaSection,
    MapaString,
)
from mapa.renderer import render_report


class TestAssemblageRecord:
    def test_from_csv_row(self):
        row = {
            "hash": "ABC123",
            "name": "foo",
            "start": "0x1000",
            "end": "0x1010",
            "source_file": "src/main.c (line 42)",
        }
        record = AssemblageRecord.from_csv_row(row, base_address=0x400000)
        assert record.sha256 == "abc123"
        assert record.start_rva == 0x1000
        assert record.end_rva == 0x1010
        assert record.address == 0x401000
        assert record.end_address == 0x401010
        assert record.source_path == "src/main.c"

    def test_source_path_without_suffix(self):
        record = AssemblageRecord(
            sha256="abc123",
            name="bar",
            start_rva=0,
            end_rva=0,
            address=0x400000,
            end_address=0x400010,
            source_file="src/bar.c",
        )
        assert record.source_path == "src/bar.c"


class TestAssemblageLoader:
    def test_load_filters_by_sha256_converts_rva_and_dedupes(self, tmp_path):
        csv_path = tmp_path / "assemblage.csv"
        csv_path.write_text(
            "file_name,path,hash,name,start,end,source_file\n"
            "sample.exe,01/sample.exe,abc123,foo,4096,4112,src/foo.c (MD5: 11)\n"
            "sample.exe,01/sample.exe,abc123,foo,4096,4112,src/foo.c (MD5: 11)\n"
            "sample.exe,01/sample.exe,abc123,foo_alias,4096,4112,src/foo_alias.c (MD5: 22)\n"
            "sample.exe,01/sample.exe,def456,skip,4096,4112,src/skip.c (MD5: 33)\n"
            "sample.exe,01/sample.exe,abc123,bar,8192,8208,src/bar.c (MD5: 44)\n",
            encoding="utf-8",
        )

        records = load_assemblage_records(
            csv_path, sample_sha256="ABC123", base_address=0x400000
        )

        assert sorted(records) == [0x401000, 0x402000]
        assert [record.name for record in records[0x401000]] == ["foo", "foo_alias"]
        assert [record.source_path for record in records[0x401000]] == [
            "src/foo.c",
            "src/foo_alias.c",
        ]
        assert records[0x402000][0].name == "bar"
        assert records[0x402000][0].address == 0x402000

    def test_load_requires_sha256(self, tmp_path):
        csv_path = tmp_path / "assemblage.csv"
        csv_path.write_text(
            "file_name,path,hash,name,start,end,source_file\n",
            encoding="utf-8",
        )

        try:
            load_assemblage_records(csv_path, sample_sha256="", base_address=0x400000)
        except ValueError as exc:
            assert "sha256" in str(exc).lower()
        else:
            assert False, "expected ValueError"


class TestRenderer:
    @staticmethod
    def _make_console() -> tuple[Console, StringIO]:
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
            width=120,
            no_color=True,
        )
        return console, buf

    @staticmethod
    def _make_assemblage_record(
        name: str, source_file: str, address: int = 0x1000
    ) -> AssemblageRecord:
        return AssemblageRecord(
            sha256="abc123",
            name=name,
            start_rva=address,
            end_rva=address + 0x10,
            address=address,
            end_address=address + 0x10,
            source_file=source_file,
        )

    def test_meta_section(self):
        report = MapaReport(
            meta=MapaMeta(
                name="test.exe",
                sha256="abc123",
                arch="x86_64",
                timestamp="2025-01-01T00:00:00",
            ),
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "test.exe" in output
        assert "abc123" in output
        assert "x86_64" in output

    def test_sections_rendered(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            sections=[
                MapaSection(address=0x1000, size=0x2000, perms="r-x"),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "0x1000" in output
        assert "r-x" in output
        assert "0x2000" in output

    def test_libraries_rendered(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            libraries=[MapaLibrary(name="KERNEL32.dll")],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "KERNEL32.dll" in output

    def test_empty_libraries(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "(none)" in output

    def test_thunk_function_with_assemblage(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="jmp_CreateFile",
                    is_thunk=True,
                    assemblage_records=[
                        self._make_assemblage_record(
                            "source_thunk", "src/thunk.c (MD5: 11)"
                        )
                    ],
                ),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "thunk" in output
        assert "jmp_CreateFile" in output
        assert "assemblage name: source_thunk" in output
        assert "assemblage file: src/thunk.c" in output

    def test_function_with_calls_strings_and_assemblage(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="main",
                    num_basic_blocks=3,
                    num_edges=4,
                    num_instructions=10,
                    total_instruction_bytes=42,
                    callers=[
                        MapaCaller(name="start", address=0x500, delta=-1, direction="↑")
                    ],
                    calls=[
                        MapaCall(
                            name="helper",
                            address=0x2000,
                            is_api=False,
                            delta=1,
                            direction="↓",
                        )
                    ],
                    apis=[MapaCall(name="CreateFileW", address=0x3000, is_api=True)],
                    strings=[MapaString(value="Hello World", address=0x4000)],
                    capa_matches=["write file"],
                    assemblage_records=[
                        self._make_assemblage_record(
                            "source_main", "src/main.c (MD5: 11)"
                        )
                    ],
                ),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "function" in output
        assert "main" in output
        assert "assemblage name: source_main" in output
        assert "assemblage file: src/main.c" in output
        assert "3 / 4 / 10 (42 bytes)" in output
        assert "xref:" in output
        assert "start" in output
        assert "calls:" in output
        assert "helper" in output
        assert "api:" in output
        assert "CreateFileW" in output
        assert "string:" in output
        assert "Hello World" in output
        assert "capa:" in output
        assert "write file" in output

    def test_ambiguous_assemblage_records_render_all(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="ida_name",
                    assemblage_records=[
                        self._make_assemblage_record("foo", "src/foo.c (MD5: 11)"),
                        self._make_assemblage_record(
                            "foo_alias", "src/foo_alias.c (MD5: 22)"
                        ),
                    ],
                ),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "function ida_name @ 0x1000" in output
        assert output.count("assemblage name:") == 2
        assert output.count("assemblage file:") == 2
        assert "foo_alias" in output
        assert "src/foo_alias.c" in output

    def test_source_file_separator_inserted_before_new_path(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="a",
                    assemblage_records=[
                        self._make_assemblage_record("a", "src/a.c (MD5: 11)")
                    ],
                ),
                MapaFunction(
                    address=0x2000,
                    name="b",
                    assemblage_records=[
                        self._make_assemblage_record(
                            "b", "src/b.c (MD5: 22)", address=0x2000
                        )
                    ],
                ),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "[ src/b.c ]" in output
        assert "[ src/a.c ]" not in output
        assert output.index("[ src/b.c ]") < output.index("function b @ 0x2000")

    def test_missing_assemblage_data_does_not_force_split(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="a1",
                    assemblage_records=[
                        self._make_assemblage_record("a1", "src/a.c (MD5: 11)")
                    ],
                ),
                MapaFunction(address=0x2000, name="unknown"),
                MapaFunction(
                    address=0x3000,
                    name="a2",
                    assemblage_records=[
                        self._make_assemblage_record(
                            "a2", "src/a.c (MD5: 22)", address=0x3000
                        )
                    ],
                ),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "[ src/a.c ]" not in output

    def test_new_source_after_missing_gap_still_splits(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="a",
                    assemblage_records=[
                        self._make_assemblage_record("a", "src/a.c (MD5: 11)")
                    ],
                ),
                MapaFunction(address=0x2000, name="unknown1"),
                MapaFunction(address=0x3000, name="unknown2"),
                MapaFunction(
                    address=0x4000,
                    name="b",
                    assemblage_records=[
                        self._make_assemblage_record(
                            "b", "src/b.c (MD5: 22)", address=0x4000
                        )
                    ],
                ),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert output.count("[ src/b.c ]") == 1
        assert "[ src/a.c ]" not in output
        assert output.index("[ src/b.c ]") < output.index("function b @ 0x4000")


class TestStringDedup:
    def test_strings_deduped_in_model(self):
        seen: set[str] = set()
        strings = ["hello", "hello", "world", "hello"]
        result = []
        for s in strings:
            stripped = s.rstrip()
            if stripped and stripped not in seen:
                seen.add(stripped)
                result.append(stripped)
        assert result == ["hello", "world"]

    def test_string_rstrip(self):
        s = "hello   \n\t"
        assert s.rstrip() == "hello"


class TestHtmlMapRenderer:
    @staticmethod
    def _make_assemblage_record(
        name: str, source_file: str, address: int
    ) -> AssemblageRecord:
        return AssemblageRecord(
            sha256="abc123",
            name=name,
            start_rva=address,
            end_rva=address + 0x10,
            address=address,
            end_address=address + 0x10,
            source_file=source_file,
        )

    @staticmethod
    def _make_report() -> MapaReport:
        return MapaReport(
            meta=MapaMeta(name="sample.exe", sha256="abc123", arch="x86_64"),
            functions=[
                MapaFunction(
                    address=0x1000,
                    name="entry",
                    strings=[MapaString(value="CreateFileW", address=0x3000, tags=("#common", "#winapi"))],
                    assemblage_records=[
                        TestHtmlMapRenderer._make_assemblage_record(
                            "entry_src", "src/core/a.c (MD5: 11)", 0x1000
                        )
                    ],
                ),
                MapaFunction(
                    address=0x2000,
                    name="worker",
                    apis=[MapaCall(name="kernel32.dll!CreateFileW", address=0x5000, is_api=True)],
                    strings=[MapaString(value="inflate", address=0x2000, tags=("#zlib",))],
                    capa_matches=["write file"],
                    assemblage_records=[
                        TestHtmlMapRenderer._make_assemblage_record(
                            "worker_src", "src/core/a.c (MD5: 22)", 0x2000
                        )
                    ],
                ),
                MapaFunction(
                    address=0x3000,
                    name="helper",
                    strings=[MapaString(value="normal", address=0x4000, tags=("#common",))],
                    assemblage_records=[
                        TestHtmlMapRenderer._make_assemblage_record(
                            "helper_src", "src/core/b.c (MD5: 33)", 0x3000
                        )
                    ],
                ),
            ],
            program_strings=[
                MapaProgramString(
                    value="inflate",
                    address=0x4000,
                    tags=("#zlib",),
                    function_addresses=(0x2000,),
                ),
                MapaProgramString(
                    value="CreateFileW",
                    address=0x3000,
                    tags=("#common", "#winapi"),
                    function_addresses=(0x1000,),
                ),
                MapaProgramString(
                    value="normal",
                    address=0x5000,
                    tags=("#common",),
                    function_addresses=(0x3000,),
                ),
                MapaProgramString(
                    value="inflate",
                    address=0x6000,
                    tags=("#zlib",),
                    function_addresses=(0x1000, 0x2000),
                ),
            ],
        )

    def test_cli_parser_accepts_html_map_output(self):
        parser = build_parser()
        args = parser.parse_args(["sample.exe", "--output", "html-map"])
        assert args.output == "html-map"

    def test_open_requires_html_map_output(self):
        with pytest.raises(ValueError, match="--open requires --output html-map"):
            validate_output_options("text", True)

    def test_write_temp_html_report(self, tmp_path):
        report_path = write_temp_html_report("<html>ok</html>", directory=tmp_path)
        assert report_path.parent == tmp_path
        assert report_path.read_text(encoding="utf-8") == "<html>ok</html>"

    def test_open_html_report_writes_temp_file_and_uses_opener(self, tmp_path):
        opened: list[str] = []

        def open_url(url: str) -> bool:
            opened.append(url)
            return True

        report_path = open_html_report(
            "<html>ok</html>",
            opener=open_url,
            directory=tmp_path,
        )
        assert report_path.parent == tmp_path
        assert report_path.read_text(encoding="utf-8") == "<html>ok</html>"
        assert opened == [report_path.as_uri()]

    def test_html_map_is_self_contained(self):
        html = render_html_map(self._make_report())
        assert "<style>" in html
        assert "<script" in html
        assert "function-grid" in html
        assert 'class="split-view"' in html
        assert 'role="separator"' in html
        assert "<link " not in html
        assert "<script src=" not in html

    def test_html_map_uses_split_panes_and_resizer(self):
        html = render_html_map(self._make_report())
        assert 'id="functions-pane"' in html
        assert 'id="strings-pane"' in html
        assert 'id="splitter"' in html
        assert "setPointerCapture" in html
        assert "pointerdown" in html

    def test_html_map_shows_tag_counts_and_legend(self):
        html = render_html_map(self._make_report())
        assert '#zlib <span class="control-count">(2)</span>' in html
        assert '#common <span class="control-count">(1)</span>' in html
        assert 'border = tag · fill = string · yellow halo = source query · dim = matches none' in html

    def test_html_map_orders_tags_by_function_count_then_name(self):
        html = render_html_map(self._make_report())
        zlib = html.index('data-tag="#zlib"')
        common = html.index('data-tag="#common"')
        winapi = html.index('data-tag="#winapi"')
        assert zlib < common < winapi

    def test_html_map_orders_program_strings_by_address_and_shows_addresses(self):
        html = render_html_map(self._make_report())
        first = html.index('data-string-address="0x3000"')
        second = html.index('data-string-address="0x4000"')
        third = html.index('data-string-address="0x5000"')
        fourth = html.index('data-string-address="0x6000"')
        assert first < second < third < fourth
        assert '0x3000' in html
        assert '0x6000' in html

    def test_html_map_string_rows_show_visible_tags(self):
        html = render_html_map(self._make_report())
        assert 'data-string-address="0x3000"' in html
        assert 'data-string-tags="#winapi"' in html
        assert 'data-string-address="0x4000"' in html
        assert 'data-string-tags="#zlib"' in html
        assert 'data-string-address="0x5000"' in html
        assert 'data-string-tags="#common"' in html
        assert 'class="string-tags">#winapi</span>' in html

    def test_html_map_exposes_source_query_input_and_prefix_logic(self):
        html = render_html_map(self._make_report())
        assert 'id="source-query"' in html
        assert 'type="text"' in html
        assert 'spellcheck="false"' in html
        assert 'src/core/a.c' in html
        assert '"sourceGroups":{"src/core/a.c":[0,1],"src/core/b.c":[2]}' in html
        assert 'startsWith(activeSourceQuery)' in html
        assert "sourceQueryInput.addEventListener('input'" in html
        assert 'yellow halo = source query' in html

    def test_html_map_function_boxes_include_source_path_attribute(self):
        html = render_html_map(self._make_report())
        assert 'data-function-index="0"' in html
        assert 'data-source-path="src/core/a.c"' in html
        assert 'data-function-index="2"' in html
        assert 'data-source-path="src/core/b.c"' in html

    def test_html_map_preserves_duplicate_values_at_distinct_addresses(self):
        html = render_html_map(self._make_report())
        assert html.count('data-string-value="inflate"') == 2

    def test_html_map_tooltip_contains_function_summary_text(self):
        html = render_html_map(self._make_report())
        assert "function worker @ 0x2000" in html
        assert "assemblage file: src/core/a.c" in html
        assert "api:       kernel32.dll!CreateFileW" in html
        assert 'string:   \\\"inflate\\\" #zlib' in html
        assert "capa:      write file" in html

    def test_html_map_visible_tag_policy_matches_text_renderer(self):
        html = render_html_map(self._make_report())
        assert 'data-tag="#winapi"' in html
        assert 'data-tag="#common"' in html
        common_control = html.index('data-tag="#common"')
        createfile_row = html.index('data-string-address="0x3000"')
        normal_row = html.index('data-string-address="0x5000"')
        assert common_control < createfile_row < normal_row

    def test_html_map_hides_common_control_when_only_hidden_common_exists(self):
        report = MapaReport(
            meta=MapaMeta(name="sample.exe", sha256="abc123"),
            functions=[MapaFunction(address=0x1000, name="entry")],
            program_strings=[
                MapaProgramString(
                    value="CreateFileW",
                    address=0x3000,
                    tags=("#common", "#winapi"),
                    function_addresses=(0x1000,),
                )
            ],
        )
        html = render_html_map(report)
        assert 'data-tag="#winapi"' in html
        assert 'data-tag="#common"' not in html
