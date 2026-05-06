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

Inverts capa's rule-centric output into a code-centric view:
instead of "rule X matched at addresses A, B, C," shows
"function at address F has these behavioral annotations on its instructions."

Requires idalib (IDA Pro 9.0+) for disassembly and pseudocode rendering.
"""

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

RULE_COLORS = ["cyan", "yellow", "magenta", "green", "red", "blue", "bright_cyan", "bright_yellow", "bright_magenta"]
RULE_SYMBOLS = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


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
class FunctionAnnotations:
    address: int
    name: str
    annotations: list[Annotation]
    rules: list[RuleSummary]


@dataclass
class DisasmLine:
    address: int
    text: str


def collect_annotations_from_match(
    match: "rd.Match",
    rule_name: str,
    rule_namespace: Optional[str],
    attack_ids: list[str],
    annotations: list[Annotation],
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
            pass
        elif isinstance(feature, frzf.MatchFeature):
            # match features are logical references to sub-rules,
            # not instruction-level evidence. skip them — the sub-rule's
            # own features will be collected when we recurse into children.
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
        collect_annotations_from_match(child, rule_name, rule_namespace, attack_ids, annotations, mode=child_mode)


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
        return "bytes", feature.bytes, desc
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


def invert_result_document(doc: "rd.ResultDocument") -> list[FunctionAnnotations]:
    """Invert rule-centric ResultDocument into function-centric annotation map."""
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
    function_rules: dict[int, list[RuleSummary]] = collections.defaultdict(list)

    for rule in rutils.capability_rules(doc):
        attack_ids = [spec.id for spec in rule.meta.attack]
        mbc_ids = [spec.id for spec in rule.meta.mbc]
        summary = RuleSummary(
            name=rule.meta.name,
            namespace=rule.meta.namespace,
            attack_ids=attack_ids,
            mbc_ids=mbc_ids,
        )

        for match_addr, match in rule.matches:
            if match_addr.type != frz.AddressType.ABSOLUTE:
                continue
            assert isinstance(match_addr.value, int)

            func_addr = match_addr.value
            if rule.meta.scopes.static == capa.rules.Scope.BASIC_BLOCK:
                func_addr = functions_by_bb.get(match_addr.value, match_addr.value)

            annotations: list[Annotation] = []
            collect_annotations_from_match(match, rule.meta.name, rule.meta.namespace, attack_ids, annotations)
            all_annotations[func_addr].extend(annotations)

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
        rules = function_rules.get(faddr, [])
        result.append(
            FunctionAnnotations(
                address=faddr,
                name="",
                annotations=deduped,
                rules=rules,
            )
        )

    return result


def get_disassembly_lines(func_start: int, func_end: int) -> list[DisasmLine]:
    """Fetch disassembly lines for a function range using idalib."""
    import idautils
    import ida_lines

    lines = []
    for ea in idautils.Heads(func_start, func_end):
        text = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)
        if text:
            lines.append(DisasmLine(address=ea, text=text))
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


def get_pseudocode_lines(func_ea: int) -> Optional[list[tuple[int, str, set[int]]]]:
    """
    Fetch pseudocode for a function.

    Returns list of (line_number, text, set_of_addresses) or None if decompiler unavailable.
    Each line has the set of addresses that map to it via get_boundaries().
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

    addr_to_lines: dict[int, set[int]] = {}
    for citem, rangeset in boundaries.items():
        coords = cfunc.find_item_coords(citem)
        if coords:
            line_no = coords[1]
            for j in range(rangeset.nranges()):
                r = rangeset.getrange(j)
                for ea in range(r.start_ea, r.end_ea):
                    addr_to_lines.setdefault(ea, set()).add(line_no)

    lines = []
    for line_no in range(pseudocode.size()):
        sl = pseudocode.at(line_no)
        import ida_lines

        text = ida_lines.tag_remove(sl.line)
        addrs_for_line: set[int] = set()
        for ea, line_set in addr_to_lines.items():
            if line_no in line_set:
                addrs_for_line.add(ea)
        lines.append((line_no, text, addrs_for_line))

    return lines


def render_function_header(
    console: rich.console.Console,
    func: FunctionAnnotations,
    rule_tag_map: dict[str, tuple[str, str]],
):
    """Render the function header with rule legend."""
    addr_str = f"0x{func.address:X}"
    name = func.name or f"sub_{func.address:X}"

    console.print()
    header = rich.text.Text()
    header.append("╔══ ", style="dim")
    header.append(f"{name}", style="bold bright_white")
    header.append(f" @ {addr_str}", style="bold")
    header.append(" ", style="dim")
    header.append("═" * max(1, 72 - len(name) - len(addr_str) - 7), style="dim")
    header.append("╗", style="dim")
    console.print(header)

    if func.rules:
        console.print(rich.text.Text("║", style="dim"))
        for rule in func.rules:
            tag, color = rule_tag_map.get(rule.name, ("?", "white"))
            line = rich.text.Text("║  ", style="dim")
            line.append(f"[{tag}]", style=f"bold {color}")
            line.append(f" {rule.name}", style="bold")
            if rule.namespace:
                line.append(f"  ({rule.namespace})", style="dim")
            if rule.attack_ids:
                line.append(f"  {', '.join(rule.attack_ids)}", style="dim italic")
            console.print(line)
        console.print(rich.text.Text("║", style="dim"))


def find_underline_target(annotation: Annotation, line_text: str) -> Optional[tuple[int, int]]:
    """
    Find the column range in line_text to underline for this annotation.

    Returns (start_col, end_col) or None if no target found.
    """
    import re

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
        patterns = []
        if num < 0x100:
            patterns.append(str(num))
        patterns.append(f"{num:X}h")
        patterns.append(f"0{num:X}h")
        patterns.append(f"0x{num:X}")
        patterns.append(f"0x{num:x}")
        for pat in patterns:
            idx = line_text.find(pat)
            if idx >= 0:
                return (idx, idx + len(pat))

    elif ft in ("offset", "operand[0].offset", "operand[1].offset", "operand[2].offset"):
        try:
            num = int(fv, 0)
        except (ValueError, TypeError):
            return None
        patterns = [f"{num:X}h", f"0{num:X}h", f"0x{num:X}", f"0x{num:x}", f"+{num:X}h", f"+0x{num:X}"]
        for pat in patterns:
            idx = line_text.find(pat)
            if idx >= 0:
                return (idx, idx + len(pat))

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

    elif ft.startswith("count(api("):
        m = re.search(r"count\(api\((.+?)\)\)", ft)
        if m:
            api_name = m.group(1)
            api_short = api_name.rsplit(".", 1)[-1] if "." in api_name else api_name
            idx = line_text.find(api_short)
            if idx >= 0:
                return (idx, idx + len(api_short))

    return None


def render_underline(
    gutter_prefix: str,
    target_start: int,
    target_end: int,
    label: str,
    tag_pairs: list[tuple[str, str]],
) -> tuple[rich.text.Text, rich.text.Text]:
    """
    Render an underline caret line pointing to columns [target_start, target_end)
    in the line above, with the annotation label.

    Produces something like:
        gutter│     ^^^^^^^^^^^
        gutter│     ╰── [A] api: CreateFile
    """
    first_color = tag_pairs[0][1]
    width = max(1, target_end - target_start)

    underline_line = rich.text.Text(gutter_prefix)
    underline_line.append(" " * target_start, style="default")
    underline_line.append("─" * width, style=first_color)

    label_line = rich.text.Text(gutter_prefix)
    label_line.append(" " * target_start, style="default")
    label_line.append("╰── ", style=first_color)

    tags_text = rich.text.Text()
    for tag, color in tag_pairs:
        tags_text.append(f"[{tag}]", style=f"bold {color}")
    label_line.append_text(tags_text)
    label_line.append(" ", style="default")
    label_line.append(label, style=first_color)

    return underline_line, label_line


def compute_windows(
    all_addresses: list[int],
    annotated_addresses: set[int],
    context: int,
) -> list[tuple[int, int, set[int]]]:
    """
    Compute display windows around annotated addresses.

    Returns list of (start_idx, end_idx, annotated_indices) for each window.
    Indices are into all_addresses list.
    """
    if not annotated_addresses:
        return []

    addr_to_idx = {addr: i for i, addr in enumerate(all_addresses)}
    annotated_indices = sorted(addr_to_idx[a] for a in annotated_addresses if a in addr_to_idx)

    if not annotated_indices:
        return []

    windows = []
    for idx in annotated_indices:
        start = max(0, idx - context)
        end = min(len(all_addresses) - 1, idx + context)
        windows.append((start, end))

    merged = [windows[0]]
    for start, end in windows[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + 2:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))

    result = []
    ann_idx_set = set(annotated_indices)
    for start, end in merged:
        window_annotated = {all_addresses[i] for i in range(start, end + 1) if i in ann_idx_set}
        result.append((start, end, window_annotated))

    return result


def group_annotations_for_display(
    annotations: list[Annotation],
    rule_tag_map: dict[str, tuple[str, str]],
) -> list[tuple[str, list[tuple[str, str]]]]:
    """
    Group annotations by (feature_type, feature_value, description) and collect
    the rule tags for each group. Returns list of (label, [(tag, color), ...]).
    """
    groups: dict[tuple[str, str, str], list[tuple[str, str]]] = collections.OrderedDict()
    for ann in annotations:
        key = (ann.feature_type, ann.feature_value, ann.description)
        tag, color = rule_tag_map.get(ann.rule_name, ("?", "white"))
        if key not in groups:
            groups[key] = []
        tag_pair = (tag, color)
        if tag_pair not in groups[key]:
            groups[key].append(tag_pair)

    result = []
    for (feat_type, feat_value, desc), tag_pairs in groups.items():
        label_parts = [feat_type]
        if feat_value:
            label_parts.append(f": {feat_value}")
        if desc:
            label_parts.append(f" = {desc}")
        result.append(("".join(label_parts), tag_pairs))
    return result


def render_disassembly(
    console: rich.console.Console,
    func: FunctionAnnotations,
    lines: list[DisasmLine],
    rule_tag_map: dict[str, tuple[str, str]],
    context: int,
):
    """Render annotated disassembly listing for a function."""
    if not lines:
        return

    annotations_by_addr: dict[int, list[Annotation]] = collections.defaultdict(list)
    for ann in func.annotations:
        annotations_by_addr[ann.address].append(ann)

    all_addresses = [dl.address for dl in lines]
    annotated_addrs = set(annotations_by_addr.keys())
    windows = compute_windows(all_addresses, annotated_addrs, context)

    if not windows:
        return

    section_header = rich.text.Text("║  ", style="dim")
    section_header.append("disassembly", style="bold underline")
    console.print(section_header)
    console.print(rich.text.Text("║", style="dim"))

    addr_to_line = {dl.address: dl for dl in lines}
    prev_end = -1

    for win_start, win_end, win_annotated in windows:
        if prev_end >= 0 and win_start > prev_end + 1:
            gap = win_start - prev_end - 1
            gap_line = rich.text.Text(" " * 12 + "│ ", style="dim")
            gap_line.append(f"... {gap} lines omitted ...", style="dim italic")
            console.print(gap_line)

        for idx in range(win_start, win_end + 1):
            addr = all_addresses[idx]
            line = addr_to_line[addr]
            is_annotated = addr in win_annotated

            line_text = rich.text.Text()
            addr_str = f"0x{addr:08X}"

            if is_annotated:
                line_text.append(f" {addr_str}", style="bold")
                line_text.append(" │ ", style="dim")
                line_text.append(line.text)
            else:
                line_text.append(f" {addr_str}", style="dim")
                line_text.append(" │ ", style="dim")
                line_text.append(line.text, style="dim")

            annots = annotations_by_addr.get(addr, [])
            if annots:
                grouped = group_annotations_for_display(annots, rule_tag_map)
                all_tags: list[tuple[str, str]] = []
                for _, tag_pairs in grouped:
                    for tp in tag_pairs:
                        if tp not in all_tags:
                            all_tags.append(tp)
                line_text.append("  ")
                for tag, color in all_tags:
                    line_text.append(f"[{tag}]", style=f"bold {color}")

            console.print(line_text)

            if is_annotated:
                gutter = " " * 12 + "│ "
                grouped = group_annotations_for_display(annots, rule_tag_map)
                for label, tag_pairs in grouped:
                    target = find_underline_target_for_group(annots, label, line.text)
                    if target:
                        ul_line, lbl_line = render_underline(gutter, target[0], target[1], label, tag_pairs)
                        console.print(ul_line)
                        console.print(lbl_line)
                    else:
                        annot_text = rich.text.Text(gutter)
                        tags_text = rich.text.Text()
                        for tag, color in tag_pairs:
                            tags_text.append(f"[{tag}]", style=f"bold {color}")
                        first_color = tag_pairs[0][1]
                        annot_text.append("╰── ", style=first_color)
                        annot_text.append_text(tags_text)
                        annot_text.append(" ", style="default")
                        annot_text.append(label, style=first_color)
                        console.print(annot_text)

        prev_end = win_end


def find_underline_target_for_group(
    annotations: list[Annotation],
    label: str,
    line_text: str,
) -> Optional[tuple[int, int]]:
    """Try to find an underline target for any annotation in this group."""
    for ann in annotations:
        target = find_underline_target(ann, line_text)
        if target:
            return target
    return None


def render_pseudocode(
    console: rich.console.Console,
    func: FunctionAnnotations,
    pseudo_lines: list[tuple[int, str, set[int]]],
    rule_tag_map: dict[str, tuple[str, str]],
    context: int,
):
    """Render annotated pseudocode listing for a function."""
    if not pseudo_lines:
        return

    annotations_by_addr: dict[int, list[Annotation]] = collections.defaultdict(list)
    for ann in func.annotations:
        annotations_by_addr[ann.address].append(ann)

    annotated_ea_set = set(annotations_by_addr.keys())

    annotated_line_nos: set[int] = set()
    annotations_by_line: dict[int, list[Annotation]] = collections.defaultdict(list)
    for line_no, _text, addrs in pseudo_lines:
        overlapping = addrs & annotated_ea_set
        if overlapping:
            annotated_line_nos.add(line_no)
            for ea in overlapping:
                for ann in annotations_by_addr[ea]:
                    if ann not in annotations_by_line[line_no]:
                        annotations_by_line[line_no].append(ann)

    if not annotated_line_nos:
        return

    section_header = rich.text.Text("║  ", style="dim")
    section_header.append("pseudocode", style="bold underline")
    console.print(section_header)
    console.print(rich.text.Text("║", style="dim"))

    all_line_nos = [ln for ln, _, _ in pseudo_lines]
    windows = compute_windows(all_line_nos, annotated_line_nos, context)

    line_map = {ln: (text, addrs) for ln, text, addrs in pseudo_lines}
    prev_end = -1

    for win_start, win_end, win_annotated in windows:
        if prev_end >= 0 and win_start > prev_end + 1:
            gap = win_start - prev_end - 1
            gap_line = rich.text.Text(" " * 8 + "│ ", style="dim")
            gap_line.append(f"... {gap} lines omitted ...", style="dim italic")
            console.print(gap_line)

        for idx in range(win_start, win_end + 1):
            line_no = all_line_nos[idx]
            text, _ = line_map[line_no]
            is_annotated = line_no in win_annotated

            line_text = rich.text.Text()
            ln_str = f"{line_no + 1:4d}"

            if is_annotated:
                line_text.append(f"  {ln_str}", style="bold")
                line_text.append(" │ ", style="dim")
                line_text.append(text)
            else:
                line_text.append(f"  {ln_str}", style="dim")
                line_text.append(" │ ", style="dim")
                line_text.append(text, style="dim")

            annots = annotations_by_line.get(line_no, [])
            if annots:
                grouped = group_annotations_for_display(annots, rule_tag_map)
                all_tags: list[tuple[str, str]] = []
                for _, tag_pairs in grouped:
                    for tp in tag_pairs:
                        if tp not in all_tags:
                            all_tags.append(tp)
                line_text.append("  ")
                for tag, color in all_tags:
                    line_text.append(f"[{tag}]", style=f"bold {color}")

            console.print(line_text)

            if is_annotated:
                gutter = " " * 8 + "│ "
                grouped = group_annotations_for_display(annots, rule_tag_map)
                for label, tag_pairs in grouped:
                    target = find_underline_target_for_group(annots, label, text)
                    if target:
                        ul_line, lbl_line = render_underline(gutter, target[0], target[1], label, tag_pairs)
                        console.print(ul_line)
                        console.print(lbl_line)
                    else:
                        annot_text = rich.text.Text(gutter)
                        tags_text = rich.text.Text()
                        for tag, color in tag_pairs:
                            tags_text.append(f"[{tag}]", style=f"bold {color}")
                        first_color = tag_pairs[0][1]
                        annot_text.append("╰── ", style=first_color)
                        annot_text.append_text(tags_text)
                        annot_text.append(" ", style="default")
                        annot_text.append(label, style=first_color)
                        console.print(annot_text)

        prev_end = win_end


def render_function_footer(console: rich.console.Console):
    console.print(rich.text.Text("╚" + "═" * 78 + "╝", style="dim"))


def render_all(
    console: rich.console.Console,
    functions: list[FunctionAnnotations],
    context: int,
    use_ida: bool = False,
    show_pseudocode: bool = True,
):
    """Render all annotated functions."""
    global_rule_tag_map: dict[str, tuple[str, str]] = {}
    all_rule_names: list[str] = []
    for func in functions:
        for rule in func.rules:
            if rule.name not in global_rule_tag_map:
                idx = len(global_rule_tag_map)
                symbol = RULE_SYMBOLS[idx % len(RULE_SYMBOLS)]
                color = RULE_COLORS[idx % len(RULE_COLORS)]
                global_rule_tag_map[rule.name] = (symbol, color)
                all_rule_names.append(rule.name)

    title = rich.text.Text()
    title.append("capa code-oriented output", style="bold bright_white")
    title.append(f"  ({len(functions)} functions, {len(global_rule_tag_map)} rules)", style="dim")
    console.print(title)
    console.print()

    if len(global_rule_tag_map) > 0:
        console.print(rich.text.Text("Rule Legend:", style="bold"))
        for rule_name in all_rule_names:
            tag, color = global_rule_tag_map[rule_name]
            legend = rich.text.Text(f"  [{tag}] ", style=f"bold {color}")
            legend.append(rule_name)
            console.print(legend)
        console.print()

    for func in functions:
        render_function_header(console, func, global_rule_tag_map)

        lines: list[DisasmLine] = []
        if use_ida:
            func_start, func_end = get_function_bounds(func.address)
            lines = get_disassembly_lines(func_start, func_end)
            func.name = get_function_name(func.address)
        if not lines:
            lines = generate_placeholder_disasm(func)

        render_disassembly(console, func, lines, global_rule_tag_map, context)

        if show_pseudocode and use_ida:
            pseudo = get_pseudocode_lines(func.address)
            if pseudo:
                console.print(rich.text.Text("║", style="dim"))
                render_pseudocode(console, func, pseudo, global_rule_tag_map, context)
            else:
                console.print(rich.text.Text("║", style="dim"))
                note = rich.text.Text("║  ", style="dim")
                note.append("(pseudocode not available)", style="dim italic")
                console.print(note)

        render_function_footer(console)


def generate_placeholder_disasm(func: FunctionAnnotations) -> list[DisasmLine]:
    """Generate placeholder disassembly lines when idalib is not available."""
    annotated_addrs = sorted({a.address for a in func.annotations})
    if not annotated_addrs:
        return []

    lines = []
    for addr in annotated_addrs:
        feats = [a for a in func.annotations if a.address == addr]
        feat = feats[0] if feats else None
        if feat:
            if feat.feature_type == "api":
                api_name = feat.feature_value.split(":")[0].strip() if ":" in feat.feature_value else feat.feature_value
                lines.append(DisasmLine(address=addr, text=f"call    {api_name}"))
            elif feat.feature_type.startswith("count(api("):
                import re

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
            elif (
                feat.feature_type == "offset"
                or feat.feature_type.startswith("operand")
                and "offset" in feat.feature_type
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
                import idaapi
                import idapro

                with STDERR_CONSOLE.status("Opening database in IDA..."):
                    idapro.open_database(str(args.input_file), run_auto_analysis=True)
                    idaapi.auto_wait()
                use_ida = True
        except Exception:
            logger.info("idalib not available, using placeholder disassembly")
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
        functions = invert_result_document(doc)

    if use_ida:
        for func in functions:
            func.name = get_function_name(func.address)

    if args.functions:
        filter_addrs = set()
        for addr_str in args.functions.split(","):
            addr_str = addr_str.strip()
            filter_addrs.add(int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str))
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
        context=args.context,
        use_ida=use_ida,
        show_pseudocode=not args.no_pseudocode,
    )

    if use_ida:
        try:
            import idapro

            idapro.close_database(save=False)
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
