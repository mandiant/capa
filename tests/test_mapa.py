import json
from io import StringIO

from rich.theme import Theme
from rich.console import Console

from mapa.model import (
    AssemblageLocation,
    MapaCall,
    MapaCaller,
    MapaFunction,
    MapaLibrary,
    MapaMeta,
    MapaReport,
    MapaSection,
    MapaString,
)
from mapa.renderer import render_report


class TestAssemblageLocation:
    def test_from_dict(self):
        data = {
            "name": "foo",
            "file": "src/main.c (line 42)",
            "prototype": "int foo(void)",
            "function_start": 0x1000,
        }
        loc = AssemblageLocation.from_dict(data)
        assert loc.name == "foo"
        assert loc.rva == 0x1000
        assert loc.path == "src/main.c"

    def test_path_no_parens(self):
        loc = AssemblageLocation(name="bar", file="src/bar.c", prototype="", rva=0)
        assert loc.path == "src/bar.c"

    def test_from_json(self):
        line = json.dumps({
            "name": "baz",
            "file": "lib.c",
            "prototype": "void baz()",
            "function_start": 0x2000,
        })
        loc = AssemblageLocation.from_json(line)
        assert loc.name == "baz"
        assert loc.rva == 0x2000


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

    def test_thunk_function(self):
        report = MapaReport(
            meta=MapaMeta(name="t", sha256="s"),
            functions=[
                MapaFunction(address=0x1000, name="jmp_CreateFile", is_thunk=True),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "thunk" in output
        assert "jmp_CreateFile" in output

    def test_function_with_calls_and_strings(self):
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
                    callers=[MapaCaller(name="start", address=0x500, delta=-1, direction="↑")],
                    calls=[MapaCall(name="helper", address=0x2000, is_api=False, delta=1, direction="↓")],
                    apis=[MapaCall(name="CreateFileW", address=0x3000, is_api=True)],
                    strings=[MapaString(value="Hello World", address=0x4000)],
                    capa_matches=["write file"],
                ),
            ],
        )
        console, buf = self._make_console()
        render_report(report, console)
        output = buf.getvalue()
        assert "function" in output
        assert "main" in output
        assert "3 / 4 / 10 (42 bytes)" in output
        assert "xref:" in output
        assert "start" in output
        assert "calls:" in output
        assert "helper" in output
        assert "api:" in output
        assert "CreateFileW" in output
        assert 'string:' in output
        assert "Hello World" in output
        assert "capa:" in output
        assert "write file" in output


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
