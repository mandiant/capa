#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
code-oriented-capa: render capa rule matches onto disassembly and pseudocode.

For each rule match, shows the contributing instructions annotated on the
disassembly and pseudocode of the matching function. A connecting spine
on the right margin links annotations back to the rule header.

Requires idalib (IDA Pro 9.0+) for disassembly and pseudocode rendering.
"""

import re
import sys
import logging
import argparse
import collections
from typing import TYPE_CHECKING, Optional
from pathlib import Path
from dataclasses import field, dataclass

import rich.text
import rich.console
import rich.logging

if TYPE_CHECKING:
    import capa.render.result_document as rd

logger = logging.getLogger(__name__)

STDERR_CONSOLE = rich.console.Console(stderr=True, highlight=False)

ANNOTATION_COLOR = "yellow"
SPINE_COLOR = "dim yellow"

IDA_TAG_ON = 0x01
IDA_TAG_OFF = 0x02
IDA_TAG_ESC = 0x03
IDA_TAG_INV = 0x04
IDA_TAG_ADDR = 0x28

IDA_COMMENT_COLORS = frozenset({0x02, 0x03, 0x04})

IDA_THEME: dict[int, str] = {
    0x01: "",  # COLOR_DEFAULT
    0x02: "bright_black italic",  # COLOR_REGCMT
    0x03: "bright_black italic",  # COLOR_RPTCMT
    0x04: "bright_black italic",  # COLOR_AUTOCMT
    0x05: "bold bright_blue",  # COLOR_INSN
    0x06: "yellow",  # COLOR_DATNAME
    0x07: "yellow",  # COLOR_DNAME
    0x08: "yellow",  # COLOR_DEMNAME
    0x09: "",  # COLOR_SYMBOL
    0x0A: "green",  # COLOR_CHAR
    0x0B: "green",  # COLOR_STRING
    0x0C: "bright_red",  # COLOR_NUMBER
    0x0D: "bright_black",  # COLOR_VOIDOP
    0x0E: "yellow",  # COLOR_CREF
    0x0F: "yellow",  # COLOR_DREF
    0x10: "yellow",  # COLOR_CREFTAIL
    0x11: "yellow",  # COLOR_DREFTAIL
    0x12: "bold red",  # COLOR_ERROR
    0x13: "bright_black",  # COLOR_PREFIX
    0x14: "bright_black",  # COLOR_BINPREF
    0x15: "bright_black",  # COLOR_EXTRA
    0x16: "",  # COLOR_ALTOP
    0x17: "bright_black",  # COLOR_HIDNAME
    0x18: "bright_cyan",  # COLOR_LIBNAME
    0x19: "bright_white",  # COLOR_LOCNAME
    0x1A: "yellow",  # COLOR_CODNAME
    0x1B: "magenta",  # COLOR_ASMDIR
    0x1C: "magenta",  # COLOR_MACRO
    0x1D: "green",  # COLOR_DSTR
    0x1E: "green",  # COLOR_DCHAR
    0x1F: "bright_red",  # COLOR_DNUM
    0x20: "magenta bold",  # COLOR_KEYWORD
    0x21: "cyan",  # COLOR_REG
    0x22: "bright_cyan",  # COLOR_IMPNAME
    0x23: "magenta",  # COLOR_SEGNAME
    0x24: "yellow",  # COLOR_UNKNAME
    0x25: "yellow",  # COLOR_CNAME
    0x26: "yellow",  # COLOR_UNAME
    0x27: "",  # COLOR_COLLAPSED
    0x29: "",  # COLOR_OPND1
    0x2A: "",  # COLOR_OPND2
    0x2B: "",  # COLOR_OPND3
    0x2C: "",  # COLOR_OPND4
    0x2D: "",  # COLOR_OPND5
    0x2E: "",  # COLOR_OPND6
    0x32: "",  # COLOR_UTF8
}


@dataclass
class Annotation:
    address: int
    feature_type: str
    feature_value: str
    description: str
    rule_name: str
    rule_namespace: Optional[str]
    attack_ids: list[str] = field(default_factory=list)


@dataclass
class RuleSummary:
    name: str
    namespace: Optional[str]
    attack_ids: list[str]
    mbc_ids: list[str]


@dataclass
class FileScopeFeature:
    feature_type: str
    feature_value: str
    rule_name: str


@dataclass
class FunctionAnnotations:
    address: int
    name: str
    annotations: list[Annotation]
    rules: list[RuleSummary]
    file_scope_features: list[FileScopeFeature] = field(default_factory=list)


@dataclass
class DisasmLine:
    address: int
    text: str
    tagged_text: str = ""


@dataclass
class BufferedLine:
    text: rich.text.Text
    kind: str  # "rule_header", "annotation_label", "normal"


FILE_SCOPE_FEATURE_TYPES = frozenset({"import", "export", "section", "function-name"})


def collect_annotations_from_match(
    match: "rd.Match",
    rule_name: str,
    rule_namespace: Optional[str],
    attack_ids: list[str],
    annotations: list[Annotation],
    file_scope_features: Optional[list[FileScopeFeature]] = None,
    mode: str = "success",
):
    """Recursively walk a Match tree, collecting leaf feature annotations."""
    import capa.helpers
    import capa.features.common
    import capa.features.freeze as frz
    import capa.render.result_document as rd
    import capa.features.freeze.features as frzf

    child_mode = mode
    if mode == "success":
        if not match.success:
            return
        if isinstance(match.node, rd.StatementNode) and match.node.statement.type == rd.CompoundStatementType.NOT:
            child_mode = "failure"
    elif mode == "failure":
        if match.success:
            return
        if isinstance(match.node, rd.StatementNode) and match.node.statement.type == rd.CompoundStatementType.NOT:
            child_mode = "success"

    if isinstance(match.node, rd.FeatureNode) and match.success:
        feature = match.node.feature
        locations = [
            loc.value for loc in match.locations if loc.type == frz.AddressType.ABSOLUTE and isinstance(loc.value, int)
        ]

        if not locations:
            if file_scope_features is not None:
                feat_type, feat_value, _ = format_feature(feature)
                if feat_type in FILE_SCOPE_FEATURE_TYPES:
                    file_scope_features.append(FileScopeFeature(feat_type, feat_value, rule_name))
        elif isinstance(feature, frzf.MatchFeature):
            pass
        elif isinstance(feature, (frzf.RegexFeature, frzf.SubstringFeature)):
            for capture, cap_locs in match.captures.items():
                for loc in cap_locs:
                    if loc.type == frz.AddressType.ABSOLUTE and isinstance(loc.value, int):
                        annotations.append(
                            Annotation(
                                address=loc.value,
                                feature_type=feature.type,
                                feature_value=f'"{capa.features.common.escape_string(capture)}"',
                                description=feature.description or "",
                                rule_name=rule_name,
                                rule_namespace=rule_namespace,
                                attack_ids=attack_ids,
                            )
                        )
        else:
            feat_type, feat_value, desc = format_feature(feature)
            for loc in locations:
                annotations.append(
                    Annotation(
                        address=loc,
                        feature_type=feat_type,
                        feature_value=feat_value,
                        description=desc,
                        rule_name=rule_name,
                        rule_namespace=rule_namespace,
                        attack_ids=attack_ids,
                    )
                )

    if (
        isinstance(match.node, rd.StatementNode)
        and isinstance(match.node.statement, rd.RangeStatement)
        and match.success
    ):
        locations = [
            loc.value for loc in match.locations if loc.type == frz.AddressType.ABSOLUTE and isinstance(loc.value, int)
        ]
        stmt = match.node.statement
        child_feat = stmt.child
        feat_type, feat_value, desc = format_feature(child_feat)
        range_desc = format_range(stmt.min, stmt.max)
        count_label = f"count({feat_type}({feat_value}))"
        for loc in locations:
            annotations.append(
                Annotation(
                    address=loc,
                    feature_type=count_label,
                    feature_value=range_desc,
                    description=stmt.description or desc,
                    rule_name=rule_name,
                    rule_namespace=rule_namespace,
                    attack_ids=attack_ids,
                )
            )

    for child in match.children:
        collect_annotations_from_match(
            child, rule_name, rule_namespace, attack_ids, annotations, file_scope_features, mode=child_mode
        )


def format_feature(feature) -> tuple[str, str, str]:
    """Extract (type_key, display_value, description) from a freeze Feature."""
    import capa.helpers
    import capa.features.common
    import capa.features.freeze.features as frzf

    key = str(feature.type)
    desc = feature.description or ""

    if isinstance(feature, frzf.APIFeature):
        return "api", feature.api, desc
    elif isinstance(feature, frzf.StringFeature):
        return "string", f'"{capa.features.common.escape_string(feature.string)}"', desc
    elif isinstance(feature, frzf.NumberFeature):
        return "number", capa.helpers.hex(feature.number), desc
    elif isinstance(feature, frzf.MnemonicFeature):
        return "mnemonic", feature.mnemonic, desc
    elif isinstance(feature, frzf.OffsetFeature):
        return "offset", capa.helpers.hex(feature.offset), desc
    elif isinstance(feature, frzf.OperandNumberFeature):
        return f"operand[{feature.index}].number", capa.helpers.hex(feature.operand_number), desc
    elif isinstance(feature, frzf.OperandOffsetFeature):
        return f"operand[{feature.index}].offset", capa.helpers.hex(feature.operand_offset), desc
    elif isinstance(feature, frzf.CharacteristicFeature):
        return "characteristic", feature.characteristic, desc
    elif isinstance(feature, frzf.ImportFeature):
        return "import", feature.import_ or "", desc
    elif isinstance(feature, frzf.ExportFeature):
        return "export", feature.export, desc
    elif isinstance(feature, frzf.SectionFeature):
        return "section", feature.section, desc
    elif isinstance(feature, frzf.FunctionNameFeature):
        return "function-name", feature.function_name, desc
    elif isinstance(feature, frzf.BytesFeature):
        raw = feature.bytes
        spaced = " ".join(raw[i : i + 2] for i in range(0, len(raw), 2)) if len(raw) > 2 else raw
        return "bytes", spaced, desc
    elif isinstance(feature, frzf.MatchFeature):
        return "match", feature.match, desc
    elif isinstance(feature, frzf.OSFeature):
        return "os", feature.os, desc
    elif isinstance(feature, frzf.ArchFeature):
        return "arch", feature.arch, desc
    elif isinstance(feature, frzf.FormatFeature):
        return "format", feature.format, desc
    elif isinstance(feature, frzf.PropertyFeature):
        access = f"/{feature.access}" if feature.access else ""
        return f"property{access}", feature.property, desc
    elif isinstance(feature, frzf.ClassFeature):
        return "class", feature.class_, desc
    elif isinstance(feature, frzf.NamespaceFeature):
        return "namespace", feature.namespace, desc
    elif isinstance(feature, frzf.BasicBlockFeature):
        return "basic block", "", desc
    elif isinstance(feature, frzf.RegexFeature):
        return "regex", feature.regex, desc
    elif isinstance(feature, frzf.SubstringFeature):
        return "substring", feature.substring, desc
    else:
        return key, str(feature), desc


def format_range(min_val: int, max_val: int) -> str:
    if min_val == max_val:
        return str(min_val)
    elif min_val == 0:
        return f"{max_val} or fewer"
    elif max_val >= (1 << 63):
        return f"{min_val} or more"
    else:
        return f"between {min_val} and {max_val}"


def invert_result_document(doc: "rd.ResultDocument") -> tuple[list[FunctionAnnotations], list[RuleSummary]]:
    """Invert rule-centric ResultDocument into function-centric annotation map.

    Returns (functions sorted by VA, rules in document order).
    """
    import capa.rules
    import capa.render.utils as rutils
    import capa.features.freeze as frz
    import capa.render.result_document as rd

    assert isinstance(doc.meta.analysis, rd.StaticAnalysis)

    functions_by_bb: dict[int, int] = {}
    function_addrs: set[int] = set()
    for finfo in doc.meta.analysis.layout.functions:
        if finfo.address.type == frz.AddressType.ABSOLUTE and isinstance(finfo.address.value, int):
            faddr = finfo.address.value
            function_addrs.add(faddr)
            for bb in finfo.matched_basic_blocks:
                if bb.address.type == frz.AddressType.ABSOLUTE and isinstance(bb.address.value, int):
                    functions_by_bb[bb.address.value] = faddr

    all_annotations: dict[int, list[Annotation]] = collections.defaultdict(list)
    all_file_scope: dict[int, list[FileScopeFeature]] = collections.defaultdict(list)
    function_rules: dict[int, list[RuleSummary]] = collections.defaultdict(list)
    doc_rule_order: list[RuleSummary] = []
    seen_rules: set[str] = set()

    for rule in rutils.capability_rules(doc):
        attack_ids = [spec.id for spec in rule.meta.attack]
        mbc_ids = [spec.id for spec in rule.meta.mbc]
        summary = RuleSummary(
            name=rule.meta.name,
            namespace=rule.meta.namespace,
            attack_ids=attack_ids,
            mbc_ids=mbc_ids,
        )

        if rule.meta.name not in seen_rules:
            seen_rules.add(rule.meta.name)
            doc_rule_order.append(summary)

        for match_addr, match in rule.matches:
            if match_addr.type != frz.AddressType.ABSOLUTE:
                continue
            assert isinstance(match_addr.value, int)

            func_addr = match_addr.value
            if rule.meta.scopes.static == capa.rules.Scope.BASIC_BLOCK:
                func_addr = functions_by_bb.get(match_addr.value, match_addr.value)

            annotations: list[Annotation] = []
            file_scope_features: list[FileScopeFeature] = []
            collect_annotations_from_match(
                match, rule.meta.name, rule.meta.namespace, attack_ids, annotations, file_scope_features
            )
            all_annotations[func_addr].extend(annotations)
            all_file_scope[func_addr].extend(file_scope_features)

            if summary not in function_rules[func_addr]:
                function_rules[func_addr].append(summary)

    result = []
    for faddr in sorted(all_annotations.keys()):
        raw_annots = sorted(all_annotations[faddr], key=lambda a: a.address)
        seen: set[tuple[int, str, str, str]] = set()
        deduped = []
        for ann in raw_annots:
            key = (ann.address, ann.feature_type, ann.feature_value, ann.rule_name)
            if key not in seen:
                seen.add(key)
                deduped.append(ann)

        fs_seen: set[tuple[str, str, str]] = set()
        fs_deduped = []
        for fs in all_file_scope.get(faddr, []):
            key_fs = (fs.feature_type, fs.feature_value, fs.rule_name)
            if key_fs not in fs_seen:
                fs_seen.add(key_fs)
                fs_deduped.append(fs)

        rules = function_rules.get(faddr, [])
        result.append(
            FunctionAnnotations(
                address=faddr,
                name="",
                annotations=deduped,
                rules=rules,
                file_scope_features=fs_deduped,
            )
        )

    return result, doc_rule_order


# ---------------------------------------------------------------------------
# IDA utility functions
# ---------------------------------------------------------------------------


def get_disassembly_lines(func_start: int, func_end: int) -> list[DisasmLine]:
    """Fetch disassembly lines for a function range using idalib."""
    import idautils
    import ida_lines

    lines = []
    for ea in idautils.Heads(func_start, func_end):
        tagged = ida_lines.generate_disasm_line(ea, 0)
        plain = strip_tags(tagged) if tagged else ""
        if plain:
            lines.append(DisasmLine(address=ea, text=plain, tagged_text=tagged or ""))
    return lines


def get_function_name(ea: int) -> str:
    """Get function name from IDA."""
    import ida_name
    import ida_funcs

    func = ida_funcs.get_func(ea)
    if func:
        name = ida_name.get_name(func.start_ea)
        if name:
            return name
    return f"sub_{ea:X}"


def get_function_bounds(ea: int) -> tuple[int, int]:
    """Get function start and end addresses."""
    import ida_funcs

    func = ida_funcs.get_func(ea)
    if func:
        return func.start_ea, func.end_ea
    return ea, ea + 1


def get_basic_block_ranges(func_ea: int) -> list[tuple[int, int]]:
    """Get basic block ranges for a function from IDA."""
    try:
        import ida_gdl
        import ida_funcs

        func = ida_funcs.get_func(func_ea)
        if not func:
            return []
        return sorted((bb.start_ea, bb.end_ea) for bb in ida_gdl.FlowChart(func))
    except ImportError:
        return []


def get_function_type(func_ea: int) -> Optional[str]:
    """Get function prototype/signature from IDA."""
    try:
        import idc
        import ida_funcs

        func = ida_funcs.get_func(func_ea)
        if not func:
            return None
        t = idc.get_type(func.start_ea)
        return t or None
    except ImportError:
        return None


def get_function_comment(func_ea: int) -> Optional[str]:
    """Get function comment from IDA."""
    try:
        import ida_funcs

        func = ida_funcs.get_func(func_ea)
        if not func:
            return None
        cmt = ida_funcs.get_func_cmt(func, False)
        if not cmt:
            cmt = ida_funcs.get_func_cmt(func, True)
        return cmt or None
    except ImportError:
        return None


def get_pseudocode_lines(func_ea: int) -> Optional[list[tuple[int, str, str, set[int]]]]:
    """
    Fetch pseudocode for a function.

    Returns list of (line_number, plain_text, tagged_text, set_of_addresses)
    or None if decompiler unavailable.
    """
    try:
        import ida_hexrays
    except ImportError:
        return None

    if not ida_hexrays.init_hexrays_plugin():
        return None

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except ida_hexrays.DecompilationFailure:
        logger.debug("decompilation failed for 0x%x", func_ea)
        return None

    if not cfunc:
        return None

    pseudocode = cfunc.get_pseudocode()
    boundaries = cfunc.get_boundaries()

    line_to_addrs: dict[int, set[int]] = {}
    for citem, rangeset in boundaries.items():
        coords = cfunc.find_item_coords(citem)
        if coords:
            line_no = coords[1]
            for j in range(rangeset.nranges()):
                r = rangeset.getrange(j)
                line_to_addrs.setdefault(line_no, set()).update(range(r.start_ea, r.end_ea))

    lines = []
    for line_no in range(pseudocode.size()):
        sl = pseudocode.at(line_no)
        tagged = sl.line
        text = strip_tags(tagged)
        lines.append((line_no, text, tagged, line_to_addrs.get(line_no, set())))

    return lines


# ---------------------------------------------------------------------------
# IDA syntax highlighting
# ---------------------------------------------------------------------------


def strip_tags(tagged_text: str, addr_width: int = 16) -> str:
    """Remove all IDA color tags, returning only the visible text.

    Raises:
        ValueError: If addr_width is not 8 or 16.
    """
    if addr_width not in (8, 16):
        raise ValueError(f"addr_width must be 8 or 16, got {addr_width}")

    parts: list[str] = []
    i = 0
    n = len(tagged_text)

    while i < n:
        ch = ord(tagged_text[i])

        if ch == IDA_TAG_ON:
            if i + 1 >= n:
                break
            tag = ord(tagged_text[i + 1])
            i += 2
            if tag == IDA_TAG_ADDR:
                i += min(addr_width, n - i)
            elif tag in IDA_COMMENT_COLORS:
                if parts and not parts[-1].isspace():
                    parts.append(" ")
        elif ch == IDA_TAG_OFF:
            if i + 1 >= n:
                break
            tag = ord(tagged_text[i + 1])
            i += 2
            if tag == IDA_TAG_ADDR:
                i += min(addr_width, n - i)
        elif ch == IDA_TAG_ESC:
            if i + 1 >= n:
                break
            parts.append(tagged_text[i + 1])
            i += 2
        elif ch == IDA_TAG_INV:
            i += 1
        else:
            parts.append(tagged_text[i])
            i += 1

    return "".join(parts)


def render_tagged_line(
    tagged_text: str,
    dimmed: bool = False,
    addr_width: int = 16,
    theme: Optional[dict[int, str]] = None,
    skip_chars: int = 0,
) -> rich.text.Text:
    """Parse IDA-style color tags into a Rich Text with syntax highlighting.

    Uses a style stack to handle nested color tags. When dimmed=True, all
    styles are overridden with "dim" for context lines. skip_chars drops
    the first N visible characters (for dedenting).

    Raises:
        ValueError: If addr_width is not 8 or 16.
    """
    if addr_width not in (8, 16):
        raise ValueError(f"addr_width must be 8 or 16, got {addr_width}")

    if theme is None:
        theme = IDA_THEME

    text = rich.text.Text()
    style_stack: list[str] = []
    buf: list[str] = []
    cur_style = ""
    i = 0
    n = len(tagged_text)
    visible_count = 0

    def _flush() -> None:
        nonlocal buf
        if buf:
            text.append("".join(buf), style="dim" if dimmed else (cur_style or "default"))
            buf = []

    while i < n:
        ch = ord(tagged_text[i])

        if ch == IDA_TAG_ON:
            if i + 1 >= n:
                break
            tag = ord(tagged_text[i + 1])
            i += 2
            if tag == IDA_TAG_ADDR:
                i += min(addr_width, n - i)
            else:
                _flush()
                if tag in IDA_COMMENT_COLORS:
                    plain = text.plain
                    if plain and not plain[-1].isspace():
                        text.append(" ", style="default")
                style_stack.append(theme.get(tag, ""))
                cur_style = style_stack[-1]
        elif ch == IDA_TAG_OFF:
            if i + 1 >= n:
                break
            tag = ord(tagged_text[i + 1])
            i += 2
            if tag == IDA_TAG_ADDR:
                i += min(addr_width, n - i)
            else:
                _flush()
                if style_stack:
                    style_stack.pop()
                cur_style = style_stack[-1] if style_stack else ""
        elif ch == IDA_TAG_ESC:
            if i + 1 >= n:
                break
            visible_count += 1
            if visible_count > skip_chars:
                buf.append(tagged_text[i + 1])
            i += 2
        elif ch == IDA_TAG_INV:
            i += 1
        else:
            visible_count += 1
            if visible_count > skip_chars:
                buf.append(tagged_text[i])
            i += 1

    _flush()
    return text


def format_disasm_rich(line: DisasmLine, is_annotated: bool, addr_width: int = 16) -> rich.text.Text:
    """Format a disassembly line as Rich Text with optional syntax highlighting."""
    if line.tagged_text:
        return render_tagged_line(line.tagged_text, dimmed=not is_annotated, addr_width=addr_width)
    elif is_annotated:
        return rich.text.Text(line.text)
    else:
        return rich.text.Text(line.text, style="dim")


# ---------------------------------------------------------------------------
# Underline target finding
# ---------------------------------------------------------------------------


def find_underline_target(annotation: Annotation, line_text: str) -> Optional[tuple[int, int]]:
    """
    Find the column range in line_text to underline for this annotation.

    Returns (start_col, end_col) or None if no target found.
    """
    ft = annotation.feature_type
    fv = annotation.feature_value

    if ft == "api":
        api_short = fv.rsplit(".", 1)[-1] if "." in fv else fv
        idx = line_text.find(api_short)
        if idx >= 0:
            return (idx, idx + len(api_short))

    elif ft == "mnemonic":
        stripped = line_text.lstrip()
        offset = len(line_text) - len(stripped)
        if stripped.lower().startswith(fv.lower()):
            return (offset, offset + len(fv))

    elif ft in ("number", "operand[0].number", "operand[1].number", "operand[2].number"):
        try:
            num = int(fv, 0)
        except (ValueError, TypeError):
            return None
        abs_num = abs(num)
        patterns = []
        if abs_num < 0x100:
            patterns.append(str(abs_num))
        patterns.append(f"{abs_num:X}h")
        patterns.append(f"0{abs_num:X}h")
        patterns.append(f"0x{abs_num:X}")
        patterns.append(f"0x{abs_num:x}")
        if num < 0:
            patterns = [f"-{p}" for p in patterns] + patterns
        for pat in patterns:
            m = re.search(r"(?<![0-9A-Fa-fx])" + re.escape(pat) + r"(?![0-9A-Fa-fxh])", line_text)
            if m:
                return (m.start(), m.end())

    elif ft in ("offset", "operand[0].offset", "operand[1].offset", "operand[2].offset"):
        try:
            num = int(fv, 0)
        except (ValueError, TypeError):
            return None
        abs_num = abs(num)
        sign = "-" if num < 0 else "+"
        patterns = [
            f"{sign}{abs_num:X}h",
            f"{sign}0{abs_num:X}h",
            f"{sign}0x{abs_num:X}",
            f"{sign}0x{abs_num:x}",
            f"{abs_num:X}h",
            f"0x{abs_num:X}",
        ]
        for pat in patterns:
            m = re.search(r"(?<![0-9A-Fa-fx])" + re.escape(pat) + r"(?![0-9A-Fa-fxh])", line_text)
            if m:
                return (m.start(), m.end())

    elif ft == "string" or ft == "regex" or ft == "substring":
        clean = fv.strip('"')
        idx = line_text.find(clean)
        if idx >= 0:
            return (idx, idx + len(clean))
        idx = line_text.find(f'"{clean}"')
        if idx >= 0:
            return (idx, idx + len(clean) + 2)

    elif ft == "characteristic":
        if fv == "nzxor":
            stripped = line_text.lstrip()
            offset = len(line_text) - len(stripped)
            if stripped.lower().startswith("xor"):
                return (offset, offset + 3)
        elif fv == "indirect call":
            m = re.search(r"call\s+(.+)", line_text, re.IGNORECASE)
            if m:
                return (m.start(), m.end())
        elif fv == "tight loop":
            stripped = line_text.lstrip()
            offset = len(line_text) - len(stripped)
            m = re.match(r"(jmp|loop)\b", stripped, re.IGNORECASE)
            if m:
                return (offset, offset + m.end())
        elif "access" in fv:
            for seg in ("fs:", "gs:", "large fs:", "large gs:"):
                idx = line_text.lower().find(seg)
                if idx >= 0:
                    return (idx, idx + len(seg))

    elif ft.startswith("count("):
        m = re.match(r"count\((\w+(?:\[\d+\]\.\w+)?)\((.+?)\)\)", ft)
        if m:
            inner_type, inner_value = m.group(1), m.group(2)
            inner_ann = Annotation(
                address=annotation.address,
                feature_type=inner_type,
                feature_value=inner_value,
                description="",
                rule_name=annotation.rule_name,
                rule_namespace=annotation.rule_namespace,
                attack_ids=annotation.attack_ids,
            )
            return find_underline_target(inner_ann, line_text)

    return None


# ---------------------------------------------------------------------------
# Windowing
# ---------------------------------------------------------------------------


def _is_label_line(text: str) -> bool:
    stripped = text.strip()
    if not stripped or not stripped.endswith(":"):
        return False
    label = stripped[:-1]
    return bool(label) and all(c.isalnum() or c == "_" for c in label)


def expand_paren_regions(
    annotated_line_nos: set[int],
    plain_texts_by_line: dict[int, str],
    all_line_nos: list[int],
) -> set[int]:
    """Expand annotated pseudocode lines to cover complete paren-balanced expressions.

    When an annotated line is inside a multi-line function call (unbalanced
    parens), walks up/down to find the matching open/close parens and marks
    all lines in that range as annotated.
    """
    if not annotated_line_nos:
        return annotated_line_nos

    depth_before: dict[int, int] = {}
    depth_after: dict[int, int] = {}
    cumulative = 0
    for ln in all_line_nos:
        depth_before[ln] = cumulative
        for ch in plain_texts_by_line.get(ln, ""):
            if ch == "(":
                cumulative += 1
            elif ch == ")":
                cumulative -= 1
        depth_after[ln] = cumulative

    idx_of = {ln: i for i, ln in enumerate(all_line_nos)}
    expanded = set(annotated_line_nos)

    for ln in sorted(annotated_line_nos):
        if depth_before[ln] <= 0 and depth_after[ln] <= 0:
            continue

        for i in range(idx_of[ln], -1, -1):
            expanded.add(all_line_nos[i])
            if depth_before[all_line_nos[i]] <= 0:
                break

        for i in range(idx_of[ln], len(all_line_nos)):
            expanded.add(all_line_nos[i])
            if depth_after[all_line_nos[i]] <= 0:
                break

    return expanded


def compute_windows(
    all_addresses: list[int],
    annotated_addresses: set[int],
    context: int,
    bb_ranges: Optional[list[tuple[int, int]]] = None,
    full_function_threshold: float = 0.5,
) -> list[tuple[int, int, set[int]]]:
    """
    Compute display windows around annotated addresses.

    When bb_ranges is provided, expands windows to include complete basic blocks.
    When total shown lines exceed full_function_threshold, shows the entire function.
    """
    if not annotated_addresses:
        return []

    addr_to_idx = {addr: i for i, addr in enumerate(all_addresses)}
    annotated_indices = sorted(addr_to_idx[a] for a in annotated_addresses if a in addr_to_idx)

    if not annotated_indices:
        return []

    expanded_indices: set[int] = set()
    if bb_ranges:
        for ann_idx in annotated_indices:
            ann_addr = all_addresses[ann_idx]
            found_bb = False
            for bb_start, bb_end in bb_ranges:
                if bb_start <= ann_addr < bb_end:
                    for i, addr in enumerate(all_addresses):
                        if bb_start <= addr < bb_end:
                            expanded_indices.add(i)
                    found_bb = True
                    break
            if not found_bb:
                expanded_indices.add(ann_idx)
    else:
        expanded_indices = set(annotated_indices)

    all_relevant = sorted(expanded_indices | set(annotated_indices))
    windows = []
    for idx in all_relevant:
        start = max(0, idx - context)
        end = min(len(all_addresses) - 1, idx + context)
        windows.append((start, end))

    if not windows:
        return []

    windows.sort()
    merged = [windows[0]]
    for start, end in windows[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + 2:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))

    total_shown = sum(end - start + 1 for start, end in merged)
    if len(all_addresses) > 0 and total_shown / len(all_addresses) > full_function_threshold:
        merged = [(0, len(all_addresses) - 1)]

    ann_idx_set = set(annotated_indices)
    result = []
    for start, end in merged:
        window_annotated = {all_addresses[i] for i in range(start, end + 1) if i in ann_idx_set}
        result.append((start, end, window_annotated))

    return result


# ---------------------------------------------------------------------------
# Annotation grouping and rendering
# ---------------------------------------------------------------------------


def group_annotations(annotations: list[Annotation]) -> list[tuple[str, list[Annotation]]]:
    """Group annotations by (feature_type, feature_value, description)."""
    groups: collections.OrderedDict[tuple[str, str, str], tuple[str, list[Annotation]]] = collections.OrderedDict()
    for ann in annotations:
        key = (ann.feature_type, ann.feature_value, ann.description)
        if key not in groups:
            label_parts = [ann.feature_type]
            if ann.feature_value:
                label_parts.append(f": {ann.feature_value}")
            if ann.description:
                label_parts.append(f" = {ann.description}")
            groups[key] = ("".join(label_parts), [])
        groups[key][1].append(ann)
    return [(label, anns) for label, anns in groups.values()]


def render_annotation_lines(
    gutter: str,
    annotations: list[Annotation],
    line_text: str,
    mirror: bool = False,
) -> list[BufferedLine]:
    """Render underline carets and annotation labels for one source line.

    When multiple annotations target the same line, renders a single combined
    underline row with vertical pipe stacking (rustc-style): all underlines
    sit directly under their tokens, then labels peel off so pipes never
    cross.

    Non-mirrored (left side): labels peel off rightmost-first with └── prefix
    extending right, pipes descend on the left.

    Mirrored (right side): labels peel off leftmost-first with ── prefix and
    ┘ suffix at the target column, pipes descend on the right as trailing │
    characters. This prevents label text from crossing unconsumed pipe
    positions.
    """
    result: list[BufferedLine] = []

    sep_idx = gutter.index("│")
    gutter_prefix = gutter[:sep_idx]
    gutter_suffix = gutter[sep_idx + 1:]

    def _gutter_text() -> rich.text.Text:
        t = rich.text.Text(gutter_prefix)
        t.append("│", style="dim")
        t.append(gutter_suffix)
        return t

    def _gutter_text_mirrored() -> rich.text.Text:
        t = rich.text.Text("─" * len(gutter_prefix), style=ANNOTATION_COLOR)
        t.append("─", style=ANNOTATION_COLOR)
        t.append("─" * len(gutter_suffix), style=ANNOTATION_COLOR)
        return t

    groups = group_annotations(annotations)

    targeted: list[tuple[int, int, str]] = []
    untargeted: list[str] = []

    for label, source_anns in groups:
        target = None
        for ann in source_anns:
            target = find_underline_target(ann, line_text)
            if target:
                break
        if target:
            targeted.append((target[0], target[1], label))
        else:
            untargeted.append(label)

    if targeted:
        targeted.sort(key=lambda t: t[0])

        if mirror:
            underline = _gutter_text()
            cursor = 0
            for col_start, col_end, _ in targeted:
                effective_start = max(col_start, cursor)
                if effective_start > cursor:
                    underline.append(" " * (effective_start - cursor), style="default")
                width = max(1, col_end - effective_start)
                if width > 1:
                    underline.append("─" * (width - 1), style=ANNOTATION_COLOR)
                underline.append("┬", style=ANNOTATION_COLOR)
                cursor = effective_start + width
            result.append(BufferedLine(underline, "normal"))

            gutter_w = len(gutter)

            for i in range(len(targeted)):
                col_end_i = targeted[i][1]
                label_text = targeted[i][2]
                target_col = col_end_i - 1

                connector_abs = gutter_w + target_col
                total_label = 3 + len(label_text)
                label_start = max(0, connector_abs - total_label)

                label_line = rich.text.Text()
                if label_start > 0:
                    label_line.append("─" * label_start, style=ANNOTATION_COLOR)
                label_line.append("── ", style=ANNOTATION_COLOR)
                label_line.append(label_text, style=ANNOTATION_COLOR)
                label_line.append("┘", style=ANNOTATION_COLOR)

                current_pos = len(label_line.plain)
                for j in range(i + 1, len(targeted)):
                    p = gutter_w + targeted[j][1] - 1
                    if p < current_pos:
                        continue
                    if p > current_pos:
                        label_line.append(" " * (p - current_pos))
                    label_line.append("│", style=ANNOTATION_COLOR)
                    current_pos = p + 1

                result.append(BufferedLine(label_line, "annotation_label"))
        else:
            underline = _gutter_text()
            cursor = 0
            for col_start, col_end, _ in targeted:
                effective_start = max(col_start, cursor)
                if effective_start > cursor:
                    underline.append(" " * (effective_start - cursor), style="default")
                width = max(1, col_end - effective_start)
                if effective_start == col_start:
                    underline.append("┬", style=ANNOTATION_COLOR)
                    if width > 1:
                        underline.append("─" * (width - 1), style=ANNOTATION_COLOR)
                else:
                    underline.append("─" * width, style=ANNOTATION_COLOR)
                cursor = effective_start + width
            result.append(BufferedLine(underline, "normal"))

            for i in range(len(targeted) - 1, -1, -1):
                col_start_i = targeted[i][0]
                label_text = targeted[i][2]

                label_line = _gutter_text()
                cursor = 0
                for j in range(i):
                    pipe_col = targeted[j][0]
                    if pipe_col >= cursor:
                        if pipe_col > cursor:
                            label_line.append(" " * (pipe_col - cursor), style="default")
                        label_line.append("│", style=ANNOTATION_COLOR)
                        cursor = pipe_col + 1

                if col_start_i > cursor:
                    label_line.append(" " * (col_start_i - cursor), style="default")

                label_line.append("└── ", style=ANNOTATION_COLOR)
                label_line.append(label_text, style=ANNOTATION_COLOR)
                result.append(BufferedLine(label_line, "annotation_label"))

    for label in untargeted:
        if mirror:
            label_line = _gutter_text_mirrored()
            label_line.append("── ", style=ANNOTATION_COLOR)
        else:
            label_line = _gutter_text()
            label_line.append("└── ", style=ANNOTATION_COLOR)
        label_line.append(label, style=ANNOTATION_COLOR)
        result.append(BufferedLine(label_line, "annotation_label"))

    return result


# ---------------------------------------------------------------------------
# Spine rendering
# ---------------------------------------------------------------------------


def add_spine(buffer: list[BufferedLine]):
    """Add connecting spine column from rule header to last annotation label."""
    header_idx = None
    last_ann_idx = None
    for i, line in enumerate(buffer):
        if line.kind == "rule_header" and header_idx is None:
            header_idx = i
        if line.kind == "annotation_label":
            last_ann_idx = i

    if header_idx is None or last_ann_idx is None:
        return

    max_width = 0
    for i in range(header_idx, last_ann_idx + 1):
        w = len(buffer[i].text.plain)
        if w > max_width:
            max_width = w

    spine_col = max(max_width + 2, 78)

    for i in range(header_idx, last_ann_idx + 1):
        line = buffer[i]
        current_width = len(line.text.plain)
        pad_needed = max(1, spine_col - current_width)

        if line.kind == "rule_header":
            line.text.append("─" * pad_needed, style=SPINE_COLOR)
            line.text.append("┐", style=SPINE_COLOR)
        elif line.kind == "annotation_label":
            connector = "┘" if i == last_ann_idx else "┤"
            line.text.append(" ", style="default")
            line.text.append("─" * max(0, pad_needed - 1), style=ANNOTATION_COLOR)
            line.text.append(connector, style=ANNOTATION_COLOR)
        else:
            line.text.append(" " * pad_needed, style="default")
            line.text.append("│", style=SPINE_COLOR)


# ---------------------------------------------------------------------------
# Side-by-side layout
# ---------------------------------------------------------------------------


def render_side_by_side(
    header: list[BufferedLine],
    left: list[BufferedLine],
    right: list[BufferedLine],
) -> list[BufferedLine]:
    """Merge header, disasm (left), and pseudocode (right) with a center spine.

    The spine runs vertically between the two columns from the rule_header
    to the last annotation on either side. Left annotations connect with
    ─┤/─┘, right annotations (rendered mirrored) connect with ├/└. The
    right-side annotation labels already contain ─ fill from mirrored
    rendering, so they're appended directly after the spine character.
    """
    left_width = max(
        max((len(bl.text.plain) for bl in header), default=0),
        max((len(bl.text.plain) for bl in left), default=0),
    )
    left_width = max(left_width + 2, 40)

    entries: list[tuple[str, BufferedLine, BufferedLine]] = []
    for bl in header:
        entries.append(("header", bl, BufferedLine(rich.text.Text(), "normal")))
    n = max(len(left), len(right))
    for i in range(n):
        lb = left[i] if i < len(left) else BufferedLine(rich.text.Text(), "normal")
        rb = right[i] if i < len(right) else BufferedLine(rich.text.Text(), "normal")
        entries.append(("body", lb, rb))

    header_idx: Optional[int] = None
    last_ann_idx: Optional[int] = None
    for i, (sec, lb, rb) in enumerate(entries):
        if lb.kind == "rule_header" and header_idx is None:
            header_idx = i
        if lb.kind == "annotation_label" or rb.kind == "annotation_label":
            last_ann_idx = i

    result: list[BufferedLine] = []
    for i, (sec, lb, rb) in enumerate(entries):
        in_spine = (
            header_idx is not None
            and last_ann_idx is not None
            and header_idx <= i <= last_ann_idx
        )
        is_last = (i == last_ann_idx)

        merged = rich.text.Text()
        merged.append_text(lb.text)
        cur_w = len(lb.text.plain)
        pad = max(0, left_width - cur_w)

        left_ann = lb.kind == "annotation_label"
        right_ann = rb.kind == "annotation_label"

        if lb.kind == "rule_header" and in_spine:
            merged.append("─" * pad, style=SPINE_COLOR)
            merged.append("┐", style=SPINE_COLOR)
        elif left_ann and right_ann and in_spine:
            connector = "┴" if is_last else "┼"
            merged.append(" ", style="default")
            merged.append("─" * max(0, pad - 1), style=ANNOTATION_COLOR)
            merged.append(connector, style=ANNOTATION_COLOR)
        elif left_ann and in_spine:
            connector = "┘" if is_last else "┤"
            merged.append(" ", style="default")
            merged.append("─" * max(0, pad - 1), style=ANNOTATION_COLOR)
            merged.append(connector, style=ANNOTATION_COLOR)
        elif right_ann and in_spine:
            connector = "└" if is_last else "├"
            merged.append(" " * pad, style="default")
            merged.append(connector, style=ANNOTATION_COLOR)
        elif in_spine:
            merged.append(" " * pad, style="default")
            merged.append("│", style=SPINE_COLOR)
        elif sec == "body":
            merged.append(" " * (pad + 1), style="default")
        else:
            merged.append(" " * (pad + 1), style="default")

        if sec == "body":
            merged.append_text(rb.text)

        result.append(BufferedLine(merged, lb.kind))

    return result


# ---------------------------------------------------------------------------
# Disassembly and pseudocode rendering (buffered)
# ---------------------------------------------------------------------------


def render_disassembly_to_buffer(
    buffer: list[BufferedLine],
    annotations: list[Annotation],
    lines: list[DisasmLine],
    context: int,
    bb_ranges: Optional[list[tuple[int, int]]] = None,
    addr_width: int = 16,
):
    """Render annotated disassembly into buffer.

    Returns:
        The gutter width (chars before the │ separator), or 0 if nothing rendered.
    """
    if not lines:
        return 0

    annotations_by_addr: dict[int, list[Annotation]] = collections.defaultdict(list)
    for ann in annotations:
        annotations_by_addr[ann.address].append(ann)

    all_addresses = [dl.address for dl in lines]
    annotated_addrs = set(annotations_by_addr.keys())
    windows = compute_windows(all_addresses, annotated_addrs, context, bb_ranges)

    if not windows:
        return 0

    max_addr = max(all_addresses)
    hex_digits = max(8, len(f"{max_addr:X}"))
    gutter_width = 1 + 2 + hex_digits
    gutter = " " * gutter_width + " │ "

    section_line = rich.text.Text("     ")
    section_line.append("disassembly", style="bold bright_blue")
    buffer.append(BufferedLine(section_line, "normal"))
    buffer.append(BufferedLine(rich.text.Text(), "normal"))

    addr_to_line = {dl.address: dl for dl in lines}
    prev_end = -1

    if windows and windows[0][0] > 0:
        above = windows[0][0]
        above_line = rich.text.Text(gutter, style="dim")
        above_line.append(f"... {above} lines above ...", style="dim italic")
        buffer.append(BufferedLine(above_line, "normal"))

    for win_start, win_end, win_annotated in windows:
        if prev_end >= 0 and win_start > prev_end + 1:
            gap = win_start - prev_end - 1
            gap_line = rich.text.Text(gutter, style="dim")
            gap_line.append(f"... {gap} lines omitted ...", style="dim italic")
            buffer.append(BufferedLine(gap_line, "normal"))

        for idx in range(win_start, win_end + 1):
            addr = all_addresses[idx]
            line = addr_to_line[addr]
            is_annotated = addr in win_annotated

            line_text = rich.text.Text()
            addr_str = f"0x{addr:0{hex_digits}X}"

            if is_annotated:
                line_text.append(f" {addr_str}", style="bold")
                line_text.append(" │ ", style="dim")
                line_text.append_text(format_disasm_rich(line, True, addr_width=addr_width))
            else:
                line_text.append(f" {addr_str}", style="dim")
                line_text.append(" │ ", style="dim")
                line_text.append_text(format_disasm_rich(line, False, addr_width=addr_width))

            buffer.append(BufferedLine(line_text, "normal"))

            annots = annotations_by_addr.get(addr, [])
            if is_annotated and annots:
                ann_lines = render_annotation_lines(gutter, annots, line.text)
                buffer.extend(ann_lines)

        prev_end = win_end

    if windows and windows[-1][1] < len(all_addresses) - 1:
        below = len(all_addresses) - 1 - windows[-1][1]
        below_line = rich.text.Text(gutter, style="dim")
        below_line.append(f"... {below} lines below ...", style="dim italic")
        buffer.append(BufferedLine(below_line, "normal"))

    return gutter_width


def render_pseudocode_to_buffer(
    buffer: list[BufferedLine],
    annotations: list[Annotation],
    pseudo_lines: list[tuple[int, str, str, set[int]]],
    context: int,
    addr_width: int = 16,
    gutter_width: int = 0,
    mirror: bool = False,
):
    """Render annotated pseudocode into buffer."""
    if not pseudo_lines:
        return

    annotations_by_addr: dict[int, list[Annotation]] = collections.defaultdict(list)
    for ann in annotations:
        annotations_by_addr[ann.address].append(ann)

    annotated_ea_set = set(annotations_by_addr.keys())

    annotated_line_nos: set[int] = set()
    annotations_by_line: dict[int, list[Annotation]] = collections.defaultdict(list)
    for line_no, _text, _tagged, addrs in pseudo_lines:
        overlapping = addrs & annotated_ea_set
        if overlapping:
            annotated_line_nos.add(line_no)
            for ea in overlapping:
                for ann in annotations_by_addr[ea]:
                    if ann not in annotations_by_line[line_no]:
                        annotations_by_line[line_no].append(ann)

    if not annotated_line_nos:
        return

    all_line_nos = [ln for ln, _, _, _ in pseudo_lines]
    plain_texts_by_line = {ln: text for ln, text, _, _ in pseudo_lines}
    annotated_line_nos = expand_paren_regions(annotated_line_nos, plain_texts_by_line, all_line_nos)

    windows = compute_windows(all_line_nos, annotated_line_nos, context)

    displayed_line_nos = set()
    for win_start, win_end, _ in windows:
        for idx in range(win_start, win_end + 1):
            displayed_line_nos.add(all_line_nos[idx])
    common_indent = min(
        (
            len(t) - len(t.lstrip())
            for ln, t in plain_texts_by_line.items()
            if ln in displayed_line_nos and t.strip() and not _is_label_line(t)
        ),
        default=0,
    )

    max_line_no = max(ln for ln, _, _, _ in pseudo_lines) + 1
    ln_digits = max(4, len(str(max_line_no)))
    # pad line number column so │ aligns with disassembly gutter
    # disassembly gutter: " 0x" + hex_digits = 1 + 2 + hex_digits = gutter_width
    # pseudocode gutter: padding + ln_digits
    ln_padding = max(1, gutter_width - ln_digits) if gutter_width > 0 else 2
    pc_gutter_width = ln_padding + ln_digits
    pc_gutter = " " * pc_gutter_width + " │ "

    section_line = rich.text.Text("     ")
    section_line.append("pseudocode", style="bold bright_blue")
    buffer.append(BufferedLine(section_line, "normal"))
    buffer.append(BufferedLine(rich.text.Text(), "normal"))

    line_map = {ln: (text, tagged, addrs) for ln, text, tagged, addrs in pseudo_lines}
    prev_end = -1

    if windows and windows[0][0] > 0:
        above = windows[0][0]
        above_line = rich.text.Text(pc_gutter, style="dim")
        above_line.append(f"... {above} lines above ...", style="dim italic")
        buffer.append(BufferedLine(above_line, "normal"))

    for win_start, win_end, win_annotated in windows:
        if prev_end >= 0 and win_start > prev_end + 1:
            gap = win_start - prev_end - 1
            gap_line = rich.text.Text(pc_gutter, style="dim")
            gap_line.append(f"... {gap} lines omitted ...", style="dim italic")
            buffer.append(BufferedLine(gap_line, "normal"))

        for idx in range(win_start, win_end + 1):
            line_no = all_line_nos[idx]
            text, tagged, _ = line_map[line_no]
            is_annotated = line_no in win_annotated

            is_label = _is_label_line(text)
            skip = 0 if is_label else common_indent
            dedented_text = text[skip:] if len(text) > skip else text

            line_text = rich.text.Text()
            ln_str = f"{line_no + 1:{ln_digits}d}"

            if is_annotated:
                line_text.append(f"{' ' * ln_padding}{ln_str}", style="bold")
                line_text.append(" │ ", style="dim")
                if tagged:
                    line_text.append_text(render_tagged_line(tagged, dimmed=False, addr_width=addr_width, skip_chars=skip))
                else:
                    line_text.append(dedented_text)
            else:
                line_text.append(f"{' ' * ln_padding}{ln_str}", style="dim")
                line_text.append(" │ ", style="dim")
                if tagged:
                    line_text.append_text(render_tagged_line(tagged, dimmed=True, addr_width=addr_width, skip_chars=skip))
                else:
                    line_text.append(dedented_text, style="dim")

            buffer.append(BufferedLine(line_text, "normal"))

            annots = annotations_by_line.get(line_no, [])
            if is_annotated and annots:
                ann_lines = render_annotation_lines(pc_gutter, annots, dedented_text, mirror=mirror)
                buffer.extend(ann_lines)

        prev_end = win_end

    if windows and windows[-1][1] < len(all_line_nos) - 1:
        below = len(all_line_nos) - 1 - windows[-1][1]
        below_line = rich.text.Text(pc_gutter, style="dim")
        below_line.append(f"... {below} lines below ...", style="dim italic")
        buffer.append(BufferedLine(below_line, "normal"))


# ---------------------------------------------------------------------------
# Top-level rendering
# ---------------------------------------------------------------------------


def render_all(
    console: rich.console.Console,
    functions: list[FunctionAnnotations],
    doc_rule_order: list[RuleSummary],
    context: int,
    use_ida: bool = False,
    show_pseudocode: bool = True,
):
    """Render all rule matches: rule-first, then functions within each rule."""
    rule_functions: dict[str, list[FunctionAnnotations]] = {}
    func_addrs_per_rule: dict[str, set[int]] = {}

    for func in functions:
        for rule in func.rules:
            if rule.name not in rule_functions:
                rule_functions[rule.name] = []
                func_addrs_per_rule[rule.name] = set()
            if func.address not in func_addrs_per_rule[rule.name]:
                func_addrs_per_rule[rule.name].add(func.address)
                rule_functions[rule.name].append(func)

    all_rules = [r for r in doc_rule_order if r.name in rule_functions]

    total_blocks = sum(len(funcs) for funcs in rule_functions.values())
    unique_funcs = len({f.address for f in functions})
    title = rich.text.Text()
    title.append("capa code-oriented output", style="bold bright_white")
    title.append(f"  ({len(all_rules)} rules, {unique_funcs} functions, {total_blocks} matches)", style="dim")
    console.print(title)

    disasm_cache: dict[int, list[DisasmLine]] = {}
    bb_cache: dict[int, Optional[list[tuple[int, int]]]] = {}
    comment_cache: dict[int, Optional[str]] = {}
    type_cache: dict[int, Optional[str]] = {}
    pseudo_cache: dict[int, Optional[list[tuple[int, str, str, set[int]]]]] = {}

    for func in functions:
        if func.address in disasm_cache:
            continue
        if use_ida:
            func_start, func_end = get_function_bounds(func.address)
            disasm_cache[func.address] = get_disassembly_lines(func_start, func_end)
            bb_cache[func.address] = get_basic_block_ranges(func.address) or None
            comment_cache[func.address] = get_function_comment(func.address)
            type_cache[func.address] = get_function_type(func.address)
            if not func.name:
                func.name = get_function_name(func.address)
        else:
            disasm_cache[func.address] = []
            bb_cache[func.address] = None
            comment_cache[func.address] = None
            type_cache[func.address] = None

    max_func_addr = max(f.address for f in functions) if functions else 0
    # idalib always uses 64-bit internal addressing, so tagged text
    # embeds 16-char hex addresses even for 32-bit binaries.
    ida_addr_width = 16

    terminal_width = console.width or 120

    for rule in all_rules:
        for func in rule_functions[rule.name]:
            rule_annots = [a for a in func.annotations if a.rule_name == rule.name]
            rule_fs = [fs for fs in func.file_scope_features if fs.rule_name == rule.name]

            addr_str = f"0x{func.address:X}"
            name = func.name or f"sub_{func.address:X}"

            console.print()

            heading = rich.text.Text(" ")
            heading.append(rule.name, style="bold bright_yellow")
            heading.append(" found in ", style="dim")
            heading.append(name, style="bold bright_yellow")
            heading.append(f" @ {addr_str}", style="bright_yellow")
            console.print(heading)

            header_buffer: list[BufferedLine] = []

            underline_line = rich.text.Text(" ")
            underline_line.append("┬", style=SPINE_COLOR)
            if len(rule.name) > 1:
                underline_line.append("─" * (len(rule.name) - 1), style=SPINE_COLOR)
            header_buffer.append(BufferedLine(underline_line, "normal"))

            connector_line = rich.text.Text(" ")
            connector_line.append("└", style=SPINE_COLOR)
            header_buffer.append(BufferedLine(connector_line, "rule_header"))

            func_type = type_cache.get(func.address)
            if func_type:
                header_buffer.append(BufferedLine(rich.text.Text(), "normal"))
                type_line = rich.text.Text("     ")
                type_line.append(func_type, style="dim")
                header_buffer.append(BufferedLine(type_line, "normal"))

            if rule_fs:
                header_buffer.append(BufferedLine(rich.text.Text(), "normal"))
                for fs in rule_fs:
                    fs_line = rich.text.Text("     ")
                    fs_line.append(f"{fs.feature_type}: {fs.feature_value}", style="dim")
                    header_buffer.append(BufferedLine(fs_line, "normal"))

            func_comment = comment_cache.get(func.address)
            if func_comment:
                header_buffer.append(BufferedLine(rich.text.Text(), "normal"))
                cmt_line = rich.text.Text("     ")
                cmt_line.append(f"; {func_comment}", style="dim italic")
                header_buffer.append(BufferedLine(cmt_line, "normal"))

            header_buffer.append(BufferedLine(rich.text.Text(), "normal"))

            disasm_lines = disasm_cache.get(func.address, [])
            if not disasm_lines:
                disasm_lines = generate_placeholder_disasm(rule_annots)
            bb_ranges = bb_cache.get(func.address)

            disasm_buffer: list[BufferedLine] = []
            disasm_gutter_width = render_disassembly_to_buffer(
                disasm_buffer, rule_annots, disasm_lines, context, bb_ranges, addr_width=ida_addr_width
            )

            pseudo: Optional[list[tuple[int, str, str, set[int]]]] = None
            if show_pseudocode and use_ida:
                if func.address not in pseudo_cache:
                    pseudo_cache[func.address] = get_pseudocode_lines(func.address)
                pseudo = pseudo_cache[func.address]

            side_by_side = False
            pseudo_buffer: list[BufferedLine] = []
            if pseudo:
                render_pseudocode_to_buffer(
                    pseudo_buffer, rule_annots, pseudo, context,
                    addr_width=ida_addr_width, gutter_width=disasm_gutter_width,
                    mirror=True,
                )
                left_w = max(
                    max((len(bl.text.plain) for bl in header_buffer), default=0),
                    max((len(bl.text.plain) for bl in disasm_buffer), default=0),
                )
                right_w = max((len(bl.text.plain) for bl in pseudo_buffer), default=0)
                needed = left_w + 3 + right_w

                if needed <= terminal_width:
                    side_by_side = True
                else:
                    pseudo_buffer = []
                    render_pseudocode_to_buffer(
                        pseudo_buffer, rule_annots, pseudo, context,
                        addr_width=ida_addr_width, gutter_width=disasm_gutter_width,
                    )

            if side_by_side:
                buffer = render_side_by_side(header_buffer, disasm_buffer, pseudo_buffer)
            elif pseudo_buffer:
                buffer = header_buffer + disasm_buffer
                buffer.append(BufferedLine(rich.text.Text(), "normal"))
                buffer.extend(pseudo_buffer)
                add_spine(buffer)
            else:
                buffer = header_buffer + disasm_buffer
                if show_pseudocode:
                    buffer.append(BufferedLine(rich.text.Text(), "normal"))
                    note = rich.text.Text("     ")
                    note.append("(pseudocode not available)", style="dim italic")
                    buffer.append(BufferedLine(note, "normal"))
                add_spine(buffer)

            for bline in buffer:
                console.print(bline.text)


# ---------------------------------------------------------------------------
# Placeholder disassembly
# ---------------------------------------------------------------------------


def generate_placeholder_disasm(annotations: list[Annotation]) -> list[DisasmLine]:
    """Generate placeholder disassembly lines when idalib is not available."""
    annotated_addrs = sorted({a.address for a in annotations})
    if not annotated_addrs:
        return []

    lines = []
    for addr in annotated_addrs:
        feats = [a for a in annotations if a.address == addr]
        feat = feats[0] if feats else None
        if feat:
            if feat.feature_type == "api":
                api_name = feat.feature_value.rsplit(".", 1)[-1] if "." in feat.feature_value else feat.feature_value
                lines.append(DisasmLine(address=addr, text=f"call    {api_name}"))
            elif feat.feature_type.startswith("count(api("):
                m = re.search(r"count\(api\((.+?)\)\)", feat.feature_type)
                api_name = m.group(1) if m else feat.feature_value
                lines.append(DisasmLine(address=addr, text=f"call    {api_name}"))
            elif feat.feature_type in ("number", "operand[0].number", "operand[1].number", "operand[2].number"):
                lines.append(DisasmLine(address=addr, text=f"push    {feat.feature_value}"))
            elif feat.feature_type == "string" or feat.feature_type == "regex" or feat.feature_type == "substring":
                lines.append(DisasmLine(address=addr, text=f"lea     eax, {feat.feature_value}"))
            elif feat.feature_type == "mnemonic":
                lines.append(DisasmLine(address=addr, text=f"{feat.feature_value}     eax, ebx"))
            elif feat.feature_type == "characteristic":
                if feat.feature_value == "indirect call":
                    lines.append(DisasmLine(address=addr, text="call    dword ptr [eax]"))
                elif feat.feature_value == "nzxor":
                    lines.append(DisasmLine(address=addr, text="xor     eax, ebx"))
                elif feat.feature_value in ("peb access", "fs access"):
                    lines.append(DisasmLine(address=addr, text="mov     eax, large fs:30h"))
                elif feat.feature_value == "gs access":
                    lines.append(DisasmLine(address=addr, text="mov     rax, gs:60h"))
                elif feat.feature_value == "cross section flow":
                    lines.append(DisasmLine(address=addr, text="jmp     far_target"))
                elif feat.feature_value == "tight loop":
                    lines.append(DisasmLine(address=addr, text="jmp     short $"))
                else:
                    lines.append(DisasmLine(address=addr, text=f"; {feat.feature_value}"))
            elif feat.feature_type == "offset" or (
                feat.feature_type.startswith("operand") and "offset" in feat.feature_type
            ):
                lines.append(DisasmLine(address=addr, text=f"mov     eax, [ecx+{feat.feature_value}]"))
            elif feat.feature_type == "bytes":
                lines.append(DisasmLine(address=addr, text=f"db      {feat.feature_value}"))
            elif feat.feature_type.startswith("count("):
                lines.append(DisasmLine(address=addr, text=f"; {feat.feature_type}: {feat.feature_value}"))
            else:
                lines.append(DisasmLine(address=addr, text=f"; [{feat.feature_type}]"))
        else:
            lines.append(DisasmLine(address=addr, text="???"))

    return lines


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def run_capa_analysis(input_path: Path, rules_path: Optional[Path]) -> "rd.ResultDocument":
    """
    Run capa analysis using idalib backend.

    idalib must be loaded before calling this function.
    Opens the IDA database directly and creates the extractor.
    """
    import idapro
    import ida_auto

    import capa.main
    import capa.rules
    import capa.loader
    import capa.capabilities.common
    import capa.render.result_document as rd
    import capa.features.extractors.ida.extractor
    from capa.features.common import OS_AUTO, FORMAT_AUTO

    with STDERR_CONSOLE.status("Opening database..."):
        ret = idapro.open_database(str(input_path), run_auto_analysis=True)
        if ret != 0:
            raise RuntimeError(f"failed to open database: {ret}")
        ida_auto.auto_wait()

    extractor = capa.features.extractors.ida.extractor.IdaFeatureExtractor()

    rules_paths = [rules_path] if rules_path else [capa.main.get_default_root() / "rules"]
    with STDERR_CONSOLE.status("Loading rules..."):
        rules = capa.rules.get_rules(rules_paths)

    with STDERR_CONSOLE.status("Finding capabilities..."):
        capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)

    with STDERR_CONSOLE.status("Building result document..."):
        meta = capa.loader.collect_metadata(
            [],
            input_path,
            FORMAT_AUTO,
            OS_AUTO,
            rules_paths,
            extractor,
            capabilities,
        )
        meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)
        doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)

    return doc


def load_result_document(json_path: Path) -> "rd.ResultDocument":
    """Load a pre-computed capa result document from JSON."""
    import capa.render.result_document as rd

    return rd.ResultDocument.from_file(json_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Render capa rule matches onto disassembly and pseudocode.",
    )
    parser.add_argument("input_file", type=Path, help="path to the input binary")
    parser.add_argument("--rules", type=Path, help="path to capa rules directory")
    parser.add_argument("--json", type=Path, dest="json_path", help="path to pre-computed capa JSON result document")
    parser.add_argument("--no-color", action="store_true", help="disable color output")
    parser.add_argument("--context", type=int, default=3, help="context lines around annotations (default: 3)")
    parser.add_argument("--no-pseudocode", action="store_true", help="skip pseudocode rendering")
    parser.add_argument("--functions", type=str, help="comma-separated function addresses to render (hex)")
    parser.add_argument("--verbose", action="store_true", help="enable debug logging")
    args = parser.parse_args(args=argv)

    if args.no_color:
        STDERR_CONSOLE.no_color = True

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(name)s - %(message)s",
        handlers=[rich.logging.RichHandler(console=STDERR_CONSOLE, show_path=False)],
    )

    import capa.render.result_document as rd

    use_ida = False

    if args.json_path:
        with STDERR_CONSOLE.status("Loading result document..."):
            doc = load_result_document(args.json_path)

        try:
            from capa.features.extractors.ida.idalib import load_idalib

            if load_idalib():
                import idapro
                import ida_auto

                with STDERR_CONSOLE.status("Opening database in IDA..."):
                    ret = idapro.open_database(str(args.input_file), run_auto_analysis=True)
                    if ret != 0:
                        raise RuntimeError(f"failed to open database: {ret}")
                    ida_auto.auto_wait()
                use_ida = True
            else:
                logger.info("idalib initialization failed, using placeholder disassembly")
        except (ImportError, RuntimeError) as e:
            logger.info("idalib not available (%s), using placeholder disassembly", e)
    else:
        try:
            from capa.features.extractors.ida.idalib import load_idalib

            if not load_idalib():
                print("error: idalib is required but not available", file=sys.stderr)
                return 1
            doc = run_capa_analysis(args.input_file, args.rules)
            use_ida = True
        except ImportError:
            print("error: idalib is required but not available", file=sys.stderr)
            return 1

    if doc.meta.flavor != rd.Flavor.STATIC:
        print("error: code-oriented output only supports static analysis results", file=sys.stderr)
        return 1

    with STDERR_CONSOLE.status("Inverting result document..."):
        functions, doc_rule_order = invert_result_document(doc)

    if use_ida:
        for func in functions:
            func.name = get_function_name(func.address)

    if args.functions:
        filter_addrs = set()
        for addr_str in args.functions.split(","):
            addr_str = addr_str.strip()
            filter_addrs.add(int(addr_str, 0) if addr_str.startswith(("0x", "0X")) else int(addr_str, 16))
        functions = [f for f in functions if f.address in filter_addrs]

    if not functions:
        print("No functions with rule matches found.", file=sys.stderr)
        return 0

    console = rich.console.Console(
        highlight=False,
        no_color=args.no_color,
        soft_wrap=True,
    )

    render_all(
        console,
        functions,
        doc_rule_order=doc_rule_order,
        context=args.context,
        use_ida=use_ida,
        show_pseudocode=not args.no_pseudocode,
    )

    if use_ida:
        try:
            import idapro

            idapro.close_database(save=False)
        except (ImportError, RuntimeError):
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
