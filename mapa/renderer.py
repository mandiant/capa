from __future__ import annotations

import contextlib

import rich.padding
from rich.text import Text
from rich.markup import escape
from rich.console import Console

from mapa.model import MapaReport


class Renderer:
    def __init__(self, console: Console):
        self.console: Console = console
        self.indent: int = 0

    @contextlib.contextmanager
    def indenting(self):
        self.indent += 1
        try:
            yield
        finally:
            self.indent -= 1

    @staticmethod
    def markup(s: str, **kwargs) -> Text:
        escaped_args = {k: (escape(v) if isinstance(v, str) else v) for k, v in kwargs.items()}
        return Text.from_markup(s.format(**escaped_args))

    def print(self, renderable, **kwargs):
        if not kwargs:
            return self.console.print(rich.padding.Padding(renderable, (0, 0, 0, self.indent * 2)))
        assert isinstance(renderable, str)
        return self.print(self.markup(renderable, **kwargs))

    def writeln(self, s: str):
        self.print(s)

    @contextlib.contextmanager
    def section(self, name):
        if isinstance(name, str):
            self.print("[title]{name}", name=name)
        elif isinstance(name, Text):
            name = name.copy()
            name.stylize_before(self.console.get_style("title"))
            self.print(name)
        else:
            raise ValueError("unexpected section name")
        with self.indenting():
            yield


def render_report(report: MapaReport, console: Console) -> None:
    o = Renderer(console)

    with o.section("meta"):
        o.writeln(f"name:   {report.meta.name}")
        o.writeln(f"sha256: {report.meta.sha256}")
        o.writeln(f"arch:   {report.meta.arch}")
        o.writeln(f"ts:     {report.meta.timestamp}")

    with o.section("sections"):
        for section in report.sections:
            o.writeln(f"- {hex(section.address)} {section.perms} {hex(section.size)}")

    with o.section("libraries"):
        for lib in report.libraries:
            static = " (static)" if lib.is_static else ""
            addr = f" at {hex(lib.load_address)}" if lib.load_address is not None else ""
            o.writeln(f"- {lib.name:<12s}{static}{addr}")
        if not report.libraries:
            o.writeln("(none)")

    func_address_to_order: dict[int, int] = {}
    for i, func in enumerate(report.functions):
        func_address_to_order[func.address] = i

    with o.section("functions"):
        last_address: int | None = None
        for func in report.functions:
            if last_address is not None:
                try:
                    last_path = report.assemblage_locations[last_address].path
                    path = report.assemblage_locations[func.address].path
                    if last_path != path:
                        o.print(o.markup("[blue]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~[/] [title]file[/] {path}\n", path=path))
                except KeyError:
                    pass
            last_address = func.address

            if func.is_thunk:
                with o.section(
                    o.markup(
                        "thunk [default]{function_name}[/] [decoration]@ {function_address}[/]",
                        function_name=func.name,
                        function_address=hex(func.address),
                    )
                ):
                    continue

            with o.section(
                o.markup(
                    "function [default]{function_name}[/] [decoration]@ {function_address}[/]",
                    function_name=func.name,
                    function_address=hex(func.address),
                )
            ):
                if func.is_thunk:
                    o.writeln("")
                    continue

                for caller in func.callers:
                    o.print(
                        "xref:    [decoration]{direction}[/] {name} [decoration]({delta:+})[/]",
                        direction=caller.direction,
                        name=caller.name,
                        delta=caller.delta,
                    )

                o.writeln(
                    f"B/E/I:     {func.num_basic_blocks} / {func.num_edges} / {func.num_instructions} ({func.total_instruction_bytes} bytes)"
                )

                for match in func.capa_matches:
                    o.writeln(f"capa:      {match}")

                for call in func.calls:
                    o.print(
                        "calls:   [decoration]{direction}[/] {name} [decoration]({delta:+})[/]",
                        direction=call.direction,
                        name=call.name,
                        delta=call.delta,
                    )

                for api in func.apis:
                    o.print(
                        "api:       {name}",
                        name=api.name,
                    )

                for s in func.strings:
                    o.print(
                        'string:   [decoration]"[/]{string}[decoration]"[/]',
                        string=s.value,
                    )

                o.print("")
