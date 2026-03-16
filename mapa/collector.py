from __future__ import annotations

import logging
from datetime import datetime, timezone

from ida_domain.database import Database
from ida_domain.flowchart import FlowChartFlags
from ida_domain.functions import FunctionFlags

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
from mapa.strings import (
    MAX_STRING_READ,
    extract_ascii_from_buf,
    extract_utf16le_from_buf,
)
from mapa.string_tags.tagger import StringTagger, load_default_tagger

logger = logging.getLogger(__name__)

THUNK_CHAIN_DEPTH_DELTA = 5


def _get_permissions_string(perm: int) -> str:
    return (
        ("r" if perm & 4 else "-")
        + ("w" if perm & 2 else "-")
        + ("x" if perm & 1 else "-")
    )


def _collect_meta(db: Database, md5: str, sha256: str) -> MapaMeta:
    name = db.path or ""
    if not md5 and db.md5:
        md5 = db.md5
    if not sha256 and db.sha256:
        sha256 = db.sha256
    arch = db.architecture or ""
    base_address = db.base_address or 0
    timestamp = datetime.now(timezone.utc).isoformat()
    return MapaMeta(
        name=name,
        sha256=sha256,
        md5=md5,
        arch=arch,
        timestamp=timestamp,
        base_address=base_address,
    )


def _collect_sections(db: Database) -> list[MapaSection]:
    sections: list[MapaSection] = []
    for seg in db.segments.get_all():
        sections.append(
            MapaSection(
                address=int(seg.start_ea),
                size=int(seg.end_ea) - int(seg.start_ea),
                perms=_get_permissions_string(int(seg.perm)),
                name=db.segments.get_name(seg) or "",
            )
        )
    return sections


def _normalize_module_name(name: str) -> str:
    """Normalize an import module name to include extension.

    IDA strips .dll from PE import module names (e.g. 'KERNEL32' instead of
    'KERNEL32.dll'). Add it back when the name has no extension.
    """
    if "." not in name:
        return f"{name}.dll".lower()
    return name.lower()


def _collect_libraries(db: Database) -> list[MapaLibrary]:
    libraries: list[MapaLibrary] = []
    for module in db.imports.get_all_modules():
        libraries.append(MapaLibrary(name=_normalize_module_name(module.name)))
    return libraries


def _build_import_index(db: Database) -> dict[int, tuple[str, str]]:
    """Build address -> (module, function_name) for all imports."""
    imports: dict[int, tuple[str, str]] = {}
    for imp in db.imports.get_all_imports():
        name = imp.name or f"ord{imp.ordinal}"
        imports[int(imp.address)] = (_normalize_module_name(imp.module_name), name)
    return imports


def _build_extern_index(db: Database) -> set[int]:
    """Collect addresses in XTRN segments."""
    externs: set[int] = set()
    for seg in db.segments.get_all():
        seg_class = db.segments.get_class(seg)
        if seg_class and seg_class.upper() == "XTRN":
            for func in db.functions.get_between(int(seg.start_ea), int(seg.end_ea)):
                externs.add(int(func.start_ea))
    return externs


def _resolve_thunk_target(
    db: Database,
    ea: int,
    import_index: dict[int, tuple[str, str]],
    extern_addrs: set[int],
) -> int | None:
    """Follow thunk chains up to THUNK_CHAIN_DEPTH_DELTA hops.

    Returns the final resolved address, or None if resolution fails.
    """
    current = ea
    for _ in range(THUNK_CHAIN_DEPTH_DELTA):
        code_refs = list(db.xrefs.code_refs_from_ea(current, flow=False))
        if len(code_refs) == 1:
            target = int(code_refs[0])
            if target in import_index or target in extern_addrs:
                return target
            target_func = db.functions.get_at(target)
            if target_func:
                flags = db.functions.get_flags(target_func)
                if flags and FunctionFlags.THUNK in flags:
                    current = target
                    continue
            return target

        data_refs = list(db.xrefs.data_refs_from_ea(current))
        if len(data_refs) == 1:
            target = int(data_refs[0])
            if target in import_index or target in extern_addrs:
                return target
            target_func = db.functions.get_at(target)
            if target_func:
                flags = db.functions.get_flags(target_func)
                if flags and FunctionFlags.THUNK in flags:
                    current = target
                    continue
            return target

        break

    return None


def _find_string_at(db: Database, ea: int) -> str | None:
    """Read bytes at the given address and check for ASCII or UTF-16 LE string."""
    try:
        buf = db.bytes.get_bytes_at(ea, MAX_STRING_READ)
    except Exception:
        return None
    if not buf:
        return None
    result = extract_ascii_from_buf(buf)
    if result is not None:
        return result
    return extract_utf16le_from_buf(buf)


def _find_data_reference_string(
    db: Database, insn_ea: int, max_depth: int = 10
) -> tuple[int, str] | None:
    """Follow single data-reference chains from an instruction to find a string."""
    current = insn_ea
    for _ in range(max_depth):
        try:
            data_refs = list(db.xrefs.data_refs_from_ea(current))
        except Exception:
            break
        if len(data_refs) != 1:
            break
        target = int(data_refs[0])
        if not db.is_valid_ea(target):
            break
        result = _find_string_at(db, target)
        if result is not None:
            return target, result
        current = target
    return None


def _merge_string_metadata(
    tags: tuple[str, ...],
    tag_matches: tuple,
    new_tags: tuple[str, ...],
    new_tag_matches: tuple,
) -> tuple[tuple[str, ...], tuple]:
    merged_tags = tuple(sorted(set(tags) | set(new_tags)))
    seen_match_keys = {match.sort_key for match in tag_matches}
    unique_new = tuple(
        match for match in new_tag_matches if match.sort_key not in seen_match_keys
    )
    return merged_tags, tag_matches + unique_new


def collect_report(
    db: Database,
    md5: str = "",
    sha256: str = "",
    matches_by_function: dict[int, set[str]] | None = None,
    assemblage_records_by_address: dict[int, list[AssemblageRecord]] | None = None,
    tagger: StringTagger | None = None,
) -> MapaReport:
    """Collect a complete mapa report from an open IDA database."""
    if matches_by_function is None:
        matches_by_function = {}
    if assemblage_records_by_address is None:
        assemblage_records_by_address = {}
    if tagger is None:
        tagger = load_default_tagger()

    meta = _collect_meta(db, md5, sha256)
    sections = _collect_sections(db)
    libraries = _collect_libraries(db)
    import_index = _build_import_index(db)
    extern_addrs = _build_extern_index(db)

    all_functions: list[tuple[int, object, bool, bool]] = []
    for func in db.functions:
        ea = int(func.start_ea)
        flags = db.functions.get_flags(func)
        is_thunk = flags is not None and FunctionFlags.THUNK in flags
        is_lib = flags is not None and FunctionFlags.LIB in flags
        all_functions.append((ea, func, is_thunk, is_lib))

    all_functions.sort(key=lambda x: x[0])

    func_address_to_order: dict[int, int] = {}
    for i, (ea, _, _, _) in enumerate(all_functions):
        func_address_to_order[ea] = i

    thunk_targets: dict[int, int] = {}
    for ea, func, is_thunk, _ in all_functions:
        if is_thunk:
            target = _resolve_thunk_target(db, ea, import_index, extern_addrs)
            if target is not None:
                thunk_targets[ea] = target

    resolved_callers: dict[int, set[int]] = {}
    resolved_callees: dict[int, list[tuple[int, bool]]] = {}

    for ea, func, is_thunk, is_lib in all_functions:
        if is_thunk or ea in import_index or ea in extern_addrs:
            continue

        fc = db.functions.get_flowchart(
            func, flags=FlowChartFlags.NOEXT | FlowChartFlags.PREDS
        )
        if fc is None:
            continue

        seen_callees: set[int] = set()
        callees: list[tuple[int, bool]] = []

        for block in fc:
            insns = block.get_instructions()
            if insns is None:
                continue
            for insn in insns:
                if not db.instructions.is_call_instruction(insn):
                    # also check for jumps to imports (thunk pattern)
                    mnem = db.instructions.get_mnemonic(insn)
                    if mnem and mnem.lower().startswith("jmp"):
                        call_targets = list(
                            db.xrefs.code_refs_from_ea(int(insn.ea), flow=False)
                        )
                    else:
                        continue
                else:
                    call_targets = list(db.xrefs.calls_from_ea(int(insn.ea)))
                    if not call_targets:
                        call_targets = list(
                            db.xrefs.code_refs_from_ea(int(insn.ea), flow=False)
                        )

                for target_ea in call_targets:
                    target_ea = int(target_ea)
                    resolved_target = target_ea

                    if target_ea in thunk_targets:
                        resolved_target = thunk_targets[target_ea]

                    if resolved_target in seen_callees:
                        continue
                    seen_callees.add(resolved_target)

                    is_api = (
                        resolved_target in import_index
                        or resolved_target in extern_addrs
                    )
                    callees.append((resolved_target, is_api))

                    if resolved_target not in resolved_callers:
                        resolved_callers[resolved_target] = set()
                    resolved_callers[resolved_target].add(ea)

        resolved_callees[ea] = callees

    mapa_functions: list[MapaFunction] = []
    program_strings_by_address: dict[int, MapaProgramString] = {}
    for ea, func, is_thunk, is_lib in all_functions:
        if ea in import_index or ea in extern_addrs:
            continue

        name = db.functions.get_name(func) or f"sub_{ea:x}"

        order = func_address_to_order[ea]

        mf = MapaFunction(
            address=ea,
            name=name,
            is_thunk=is_thunk,
            is_library=is_lib,
            assemblage_records=list(assemblage_records_by_address.get(ea, [])),
        )

        if is_thunk:
            mapa_functions.append(mf)
            continue

        fc = db.functions.get_flowchart(
            func, flags=FlowChartFlags.NOEXT | FlowChartFlags.PREDS
        )
        if fc is not None:
            num_blocks = 0
            num_edges = 0
            num_insns = 0
            total_bytes = 0

            for block in fc:
                num_blocks += 1
                num_edges += block.count_successors()
                insns = block.get_instructions()
                if insns is None:
                    continue
                for insn in insns:
                    num_insns += 1
                    insn_size = db.heads.size(int(insn.ea))
                    total_bytes += insn_size

            mf.num_basic_blocks = num_blocks
            mf.num_edges = num_edges
            mf.num_instructions = num_insns
            mf.total_instruction_bytes = total_bytes

        for caller_ea in sorted(resolved_callers.get(ea, set())):
            if caller_ea not in func_address_to_order:
                continue
            caller_order = func_address_to_order[caller_ea]
            delta = caller_order - order
            direction = "↑" if delta < 0 else "↓"
            caller_func = db.functions.get_at(caller_ea)
            caller_name = (
                db.functions.get_name(caller_func)
                if caller_func
                else f"sub_{caller_ea:x}"
            )
            mf.callers.append(
                MapaCaller(
                    name=caller_name or f"sub_{caller_ea:x}",
                    address=caller_ea,
                    delta=delta,
                    direction=direction,
                )
            )

        for target_ea, is_api in resolved_callees.get(ea, []):
            if is_api:
                if target_ea in import_index:
                    module_name, func_name = import_index[target_ea]
                    api_name = f"{module_name}!{func_name}"
                else:
                    target_func = db.functions.get_at(target_ea)
                    api_name = (
                        db.functions.get_name(target_func)
                        if target_func
                        else f"sub_{target_ea:x}"
                    )
                    api_name = api_name or f"sub_{target_ea:x}"
                mf.apis.append(
                    MapaCall(
                        name=api_name,
                        address=target_ea,
                        is_api=True,
                    )
                )
            else:
                if target_ea not in func_address_to_order:
                    continue
                target_order = func_address_to_order[target_ea]
                delta = target_order - order
                direction = "↑" if delta < 0 else "↓"
                target_func = db.functions.get_at(target_ea)
                target_name = (
                    db.functions.get_name(target_func)
                    if target_func
                    else f"sub_{target_ea:x}"
                )
                mf.calls.append(
                    MapaCall(
                        name=target_name or f"sub_{target_ea:x}",
                        address=target_ea,
                        is_api=False,
                        delta=delta,
                        direction=direction,
                    )
                )

        if fc is not None:
            seen_strings: dict[str, MapaString] = {}
            fc2 = db.functions.get_flowchart(
                func, flags=FlowChartFlags.NOEXT | FlowChartFlags.PREDS
            )
            if fc2 is not None:
                for block in fc2:
                    insns = block.get_instructions()
                    if insns is None:
                        continue
                    for insn in insns:
                        string_result = _find_data_reference_string(db, int(insn.ea))
                        if string_result is None:
                            continue
                        string_ea, raw = string_result
                        tag_result = tagger.tag_string(raw)
                        display = raw.rstrip()
                        if not display:
                            continue
                        if display in seen_strings:
                            existing = seen_strings[display]
                            existing.tags, existing.tag_matches = _merge_string_metadata(
                                existing.tags,
                                existing.tag_matches,
                                tag_result.tags,
                                tag_result.matches,
                            )
                            existing.address = min(existing.address, string_ea)
                        else:
                            ms = MapaString(
                                value=display,
                                address=string_ea,
                                tags=tuple(sorted(set(tag_result.tags))),
                                tag_matches=tag_result.matches,
                            )
                            seen_strings[display] = ms
                            mf.strings.append(ms)

                        if string_ea in program_strings_by_address:
                            existing_program_string = program_strings_by_address[string_ea]
                            existing_program_string.tags, existing_program_string.tag_matches = _merge_string_metadata(
                                existing_program_string.tags,
                                existing_program_string.tag_matches,
                                tag_result.tags,
                                tag_result.matches,
                            )
                            existing_program_string.function_addresses = tuple(
                                sorted(
                                    set(existing_program_string.function_addresses)
                                    | {ea}
                                )
                            )
                        else:
                            program_strings_by_address[string_ea] = MapaProgramString(
                                value=display,
                                address=string_ea,
                                tags=tuple(sorted(set(tag_result.tags))),
                                tag_matches=tag_result.matches,
                                function_addresses=(ea,),
                            )

        mf.capa_matches = sorted(matches_by_function.get(ea, set()))
        mapa_functions.append(mf)

    return MapaReport(
        meta=meta,
        sections=sections,
        libraries=libraries,
        functions=mapa_functions,
        program_strings=sorted(
            program_strings_by_address.values(),
            key=lambda string: string.address,
        ),
    )
