from __future__ import annotations

import contextlib

import rich.padding
from rich.console import Console
from rich.markup import escape
from rich.text import Text

from mapa.model import MapaFunction, MapaReport, MapaString


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
        escaped_args = {
            k: (escape(v) if isinstance(v, str) else v) for k, v in kwargs.items()
        }
        return Text.from_markup(s.format(**escaped_args))

    def print(self, renderable, **kwargs):
        if not kwargs:
            return self.console.print(
                rich.padding.Padding(renderable, (0, 0, 0, self.indent * 2))
            )
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


def _visible_tags(tags: tuple[str, ...]) -> list[str]:
    tag_set = set(tags)
    has_specific = any(t != "#common" for t in tag_set)
    result = []
    for t in tags:
        if t == "#common" and has_specific:
            continue
        result.append(t)
    return result


def _render_string_line(o: Renderer, value: str, tags: list[str]) -> Text:
    left = Text.from_markup(
        'string:   [decoration]"[/]{string}[decoration]"[/]'.format(
            string=escape(value)
        )
    )
    right = Text(" ".join(tags), style="dim")

    available = o.console.size.width - (o.indent * 2)
    min_gap = 1
    right_len = right.cell_len
    max_left = available - right_len - min_gap
    if max_left < 12:
        combined = left.copy()
        combined.append(" ")
        combined.append(right)
        return combined

    if left.cell_len > max_left:
        left.truncate(max_left - 1, overflow="ellipsis")

    padding = available - left.cell_len - right_len
    combined = left.copy()
    combined.append(" " * padding)
    combined.append(right)
    return combined


def _get_primary_source_path(func) -> str | None:
    if not func.assemblage_records:
        return None
    source_path = func.assemblage_records[0].source_path
    if not source_path:
        return None
    return source_path


def _render_source_path_separator(o: Renderer, source_path: str) -> Text:
    label = f"[ {source_path} ]"
    available = max(0, o.console.size.width - (o.indent * 2))
    if available <= len(label) + 2:
        return Text(label, style="decoration")

    rule_len = available - len(label) - 2
    left_len = rule_len // 2
    right_len = rule_len - left_len

    rendered = Text("-" * left_len, style="decoration")
    rendered.append(" ")
    rendered.append(label, style="decoration")
    rendered.append(" ")
    rendered.append("-" * right_len, style="decoration")
    return rendered


def _format_function_heading(func: MapaFunction) -> str:
    kind = "thunk" if func.is_thunk else "function"
    return f"{kind} {func.name} @ {hex(func.address)}"


def _iter_function_rows(func: MapaFunction):
    for record in func.assemblage_records:
        yield "assemblage", record

    if func.is_thunk:
        return

    for caller in func.callers:
        yield "caller", caller

    yield "metrics", None

    for match in func.capa_matches:
        yield "capa", match

    for call in func.calls:
        yield "call", call

    for api in func.apis:
        yield "api", api

    for string in func.strings:
        yield "string", string


def _render_plain_string_line(string: MapaString) -> str:
    visible_tags = _visible_tags(string.tags)
    line = f'string:   "{string.value}"'
    if visible_tags:
        line += f" {' '.join(visible_tags)}"
    return line


def render_function_summary_text(func: MapaFunction) -> str:
    lines = [_format_function_heading(func)]
    for kind, value in _iter_function_rows(func):
        if kind == "assemblage":
            lines.append(f"assemblage name: {value.name}")
            lines.append(f"assemblage file: {value.source_path}")
        elif kind == "caller":
            lines.append(
                f"xref:    {value.direction} {value.name} ({value.delta:+})"
            )
        elif kind == "metrics":
            lines.append(
                f"B/E/I:     {func.num_basic_blocks} / {func.num_edges} / {func.num_instructions} ({func.total_instruction_bytes} bytes)"
            )
        elif kind == "capa":
            lines.append(f"capa:      {value}")
        elif kind == "call":
            lines.append(
                f"calls:   {value.direction} {value.name} ({value.delta:+})"
            )
        elif kind == "api":
            lines.append(f"api:       {value.name}")
        elif kind == "string":
            lines.append(_render_plain_string_line(value))
        else:
            raise ValueError(f"unexpected function row kind: {kind}")
    return "\n".join(lines)


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
            addr = (
                f" at {hex(lib.load_address)}" if lib.load_address is not None else ""
            )
            o.writeln(f"- {lib.name:<12s}{static}{addr}")
        if not report.libraries:
            o.writeln("(none)")

    with o.section("functions"):
        last_source_path: str | None = None
        for func in report.functions:
            source_path = _get_primary_source_path(func)
            if source_path is not None:
                if last_source_path is not None and source_path != last_source_path:
                    o.print(_render_source_path_separator(o, source_path))
                last_source_path = source_path

            with o.section(
                o.markup(
                    "{function_kind} [default]{function_name}[/] [decoration]@ {function_address}[/]",
                    function_kind="thunk" if func.is_thunk else "function",
                    function_name=func.name,
                    function_address=hex(func.address),
                )
            ):
                for kind, value in _iter_function_rows(func):
                    if kind == "assemblage":
                        o.writeln(f"assemblage name: {value.name}")
                        o.writeln(f"assemblage file: {value.source_path}")
                    elif kind == "caller":
                        o.print(
                            "xref:    [decoration]{direction}[/] {name} [decoration]({delta:+})[/]",
                            direction=value.direction,
                            name=value.name,
                            delta=value.delta,
                        )
                    elif kind == "metrics":
                        o.writeln(
                            f"B/E/I:     {func.num_basic_blocks} / {func.num_edges} / {func.num_instructions} ({func.total_instruction_bytes} bytes)"
                        )
                    elif kind == "capa":
                        o.writeln(f"capa:      {value}")
                    elif kind == "call":
                        o.print(
                            "calls:   [decoration]{direction}[/] {name} [decoration]({delta:+})[/]",
                            direction=value.direction,
                            name=value.name,
                            delta=value.delta,
                        )
                    elif kind == "api":
                        o.print(
                            "api:       {name}",
                            name=value.name,
                        )
                    elif kind == "string":
                        visible_tags = _visible_tags(value.tags)
                        if visible_tags:
                            o.print(_render_string_line(o, value.value, visible_tags))
                        else:
                            o.print(
                                'string:   [decoration]"[/]{string}[decoration]"[/]',
                                string=value.value,
                            )
                    else:
                        raise ValueError(f"unexpected function row kind: {kind}")

                if not func.is_thunk:
                    o.print("")
