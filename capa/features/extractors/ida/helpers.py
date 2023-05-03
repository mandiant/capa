# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Any, Dict, Tuple, Iterator, Optional

import idc
import idaapi
import idautils
import ida_bytes
import ida_segment

from capa.features.address import AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import FunctionHandle


def find_byte_sequence(start: int, end: int, seq: bytes) -> Iterator[int]:
    """yield all ea of a given byte sequence

    args:
        start: min virtual address
        end: max virtual address
        seq: bytes to search e.g. b"\x01\x03"
    """
    seqstr = " ".join([f"{b:02x}" for b in seq])
    while True:
        # TODO find_binary: Deprecated. Please use ida_bytes.bin_search() instead.
        ea = idaapi.find_binary(start, end, seqstr, 0, idaapi.SEARCH_DOWN)
        if ea == idaapi.BADADDR:
            break
        start = ea + 1
        yield ea


def get_functions(
    start: Optional[int] = None, end: Optional[int] = None, skip_thunks: bool = False, skip_libs: bool = False
) -> Iterator[FunctionHandle]:
    """get functions, range optional

    args:
        start: min virtual address
        end: max virtual address
    """
    for ea in idautils.Functions(start=start, end=end):
        f = idaapi.get_func(ea)
        if not (skip_thunks and (f.flags & idaapi.FUNC_THUNK) or skip_libs and (f.flags & idaapi.FUNC_LIB)):
            yield FunctionHandle(address=AbsoluteVirtualAddress(ea), inner=f)


def get_segments(skip_header_segments=False) -> Iterator[idaapi.segment_t]:
    """get list of segments (sections) in the binary image

    args:
        skip_header_segments: IDA may load header segments - skip if set
    """
    for n in range(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)
        if seg and not (skip_header_segments and seg.is_header_segm()):
            yield seg


def get_segment_buffer(seg: idaapi.segment_t) -> bytes:
    """return bytes stored in a given segment

    decrease buffer size until IDA is able to read bytes from the segment
    """
    buff = b""
    sz = seg.end_ea - seg.start_ea

    while sz > 0:
        buff = idaapi.get_bytes(seg.start_ea, sz)
        if buff:
            break
        sz -= 0x1000

    # IDA returns None if get_bytes fails, so convert for consistent return type
    return buff if buff else b""


def get_file_imports() -> Dict[int, Tuple[str, str, int]]:
    """get file imports"""
    imports = {}

    for idx in range(idaapi.get_import_module_qty()):
        library = idaapi.get_import_module_name(idx)

        if not library:
            continue

        # IDA uses section names for the library of ELF imports, like ".dynsym".
        # These are not useful to us, we may need to expand this list over time
        # TODO: exhaust this list, see #1419
        if library == ".dynsym":
            library = ""

        def inspect_import(ea, function, ordinal):
            if function and function.startswith("__imp_"):
                # handle mangled PE imports
                function = function[len("__imp_") :]

            if function and "@@" in function:
                # handle mangled ELF imports, like "fopen@@glibc_2.2.5"
                function, _, _ = function.partition("@@")

            imports[ea] = (library.lower(), function, ordinal)
            return True

        idaapi.enum_import_names(idx, inspect_import)

    return imports


def get_file_externs() -> Dict[int, Tuple[str, str, int]]:
    externs = {}

    for seg in get_segments(skip_header_segments=True):
        if not (seg.type == ida_segment.SEG_XTRN):
            continue

        for ea in idautils.Functions(seg.start_ea, seg.end_ea):
            externs[ea] = ("", idaapi.get_func_name(ea), -1)

    return externs


def get_instructions_in_range(start: int, end: int) -> Iterator[idaapi.insn_t]:
    """yield instructions in range

    args:
        start: virtual address (inclusive)
        end: virtual address (exclusive)
    """
    for head in idautils.Heads(start, end):
        insn = idautils.DecodeInstruction(head)
        if insn:
            yield insn


def is_operand_equal(op1: idaapi.op_t, op2: idaapi.op_t) -> bool:
    """compare two IDA op_t"""
    if op1.flags != op2.flags:
        return False

    if op1.dtype != op2.dtype:
        return False

    if op1.type != op2.type:
        return False

    if op1.reg != op2.reg:
        return False

    if op1.phrase != op2.phrase:
        return False

    if op1.value != op2.value:
        return False

    if op1.addr != op2.addr:
        return False

    return True


def is_basic_block_equal(bb1: idaapi.BasicBlock, bb2: idaapi.BasicBlock) -> bool:
    """compare two IDA BasicBlock"""
    if bb1.start_ea != bb2.start_ea:
        return False

    if bb1.end_ea != bb2.end_ea:
        return False

    if bb1.type != bb2.type:
        return False

    return True


def basic_block_size(bb: idaapi.BasicBlock) -> int:
    """calculate size of basic block"""
    return bb.end_ea - bb.start_ea


def read_bytes_at(ea: int, count: int) -> bytes:
    """ """
    # check if byte has a value, see get_wide_byte doc
    if not idc.is_loaded(ea):
        return b""

    segm_end = idc.get_segm_end(ea)
    if ea + count > segm_end:
        return idc.get_bytes(ea, segm_end - ea)
    else:
        return idc.get_bytes(ea, count)


def find_string_at(ea: int, min_: int = 4) -> str:
    """check if ASCII string exists at a given virtual address"""
    found = idaapi.get_strlit_contents(ea, -1, idaapi.STRTYPE_C)
    if found and len(found) >= min_:
        try:
            found = found.decode("ascii")
            # hacky check for IDA bug; get_strlit_contents also reads Unicode as
            # myy__uunniiccoodde when searching in ASCII mode so we check for that here
            # and return the fixed up value
            if len(found) >= 3 and found[1::2] == found[2::2]:
                found = found[0] + found[1::2]
            return found
        except UnicodeDecodeError:
            pass
    return ""


def get_op_phrase_info(op: idaapi.op_t) -> Dict:
    """parse phrase features from operand

    Pretty much dup of sark's implementation:
        https://github.com/tmr232/Sark/blob/master/sark/code/instruction.py#L28-L73
    """
    if op.type not in (idaapi.o_phrase, idaapi.o_displ):
        return {}

    scale = 1 << ((op.specflag2 & 0xC0) >> 6)
    # IDA ea_t may be 32- or 64-bit; we assume displacement can only be 32-bit
    offset = op.addr & 0xFFFFFFFF

    if op.specflag1 == 0:
        index = None
        base = op.reg
    elif op.specflag1 == 1:
        index = (op.specflag2 & 0x38) >> 3
        base = (op.specflag2 & 0x07) >> 0

        if op.reg == 0xC:
            if base & 4:
                base += 8
            if index & 4:
                index += 8
    else:
        return {}

    if (index == base == idautils.procregs.sp.reg) and (scale == 1):
        # HACK: This is a really ugly hack. For some reason, phrases of the form `[esp + ...]` (`sp`, `rsp` as well)
        # set both the `index` and the `base` to `esp`. This is not significant, as `esp` cannot be used as an
        # index, but it does cause issues with the parsing.
        # This is only relevant to Intel architectures.
        index = None

    return {"base": base, "index": index, "scale": scale, "offset": offset}


def is_op_write(insn: idaapi.insn_t, op: idaapi.op_t) -> bool:
    """Check if an operand is written to (destination operand)"""
    return idaapi.has_cf_chg(insn.get_canon_feature(), op.n)


def is_op_read(insn: idaapi.insn_t, op: idaapi.op_t) -> bool:
    """Check if an operand is read from (source operand)"""
    return idaapi.has_cf_use(insn.get_canon_feature(), op.n)


def is_op_offset(insn: idaapi.insn_t, op: idaapi.op_t) -> bool:
    """Check is an operand has been marked as an offset (by auto-analysis or manually)"""
    flags = idaapi.get_flags(insn.ea)
    return ida_bytes.is_off(flags, op.n)


def is_sp_modified(insn: idaapi.insn_t) -> bool:
    """determine if instruction modifies SP, ESP, RSP"""
    for op in get_insn_ops(insn, target_ops=(idaapi.o_reg,)):
        if op.reg == idautils.procregs.sp.reg and is_op_write(insn, op):
            # register is stack and written
            return True
    return False


def is_bp_modified(insn: idaapi.insn_t) -> bool:
    """check if instruction modifies BP, EBP, RBP"""
    for op in get_insn_ops(insn, target_ops=(idaapi.o_reg,)):
        if op.reg == idautils.procregs.bp.reg and is_op_write(insn, op):
            # register is base and written
            return True
    return False


def is_frame_register(reg: int) -> bool:
    """check if register is sp or bp"""
    return reg in (idautils.procregs.sp.reg, idautils.procregs.bp.reg)


def get_insn_ops(insn: idaapi.insn_t, target_ops: Optional[Tuple[Any]] = None) -> idaapi.op_t:
    """yield op_t for instruction, filter on type if specified"""
    for op in insn.ops:
        if op.type == idaapi.o_void:
            # avoid looping all 6 ops if only subset exists
            break
        if target_ops and op.type not in target_ops:
            continue
        yield op


def is_op_stack_var(ea: int, index: int) -> bool:
    """check if operand is a stack variable"""
    return idaapi.is_stkvar(idaapi.get_flags(ea), index)


def mask_op_val(op: idaapi.op_t) -> int:
    """mask value by data type

    necessary due to a bug in AMD64

    Example:
        .rsrc:0054C12C mov [ebp+var_4], 0FFFFFFFFh

        insn.Op2.dtype == idaapi.dt_dword
        insn.Op2.value == 0xffffffffffffffff
    """
    masks = {
        idaapi.dt_byte: 0xFF,
        idaapi.dt_word: 0xFFFF,
        idaapi.dt_dword: 0xFFFFFFFF,
        idaapi.dt_qword: 0xFFFFFFFFFFFFFFFF,
    }
    return masks.get(op.dtype, op.value) & op.value


def is_function_recursive(f: idaapi.func_t) -> bool:
    """check if function is recursive"""
    for ref in idautils.CodeRefsTo(f.start_ea, True):
        if f.contains(ref):
            return True
    return False


def is_basic_block_tight_loop(bb: idaapi.BasicBlock) -> bool:
    """check basic block loops to self

    true if last instruction in basic block branches to basic block start
    """
    bb_end = idc.prev_head(bb.end_ea)
    if bb.start_ea < bb_end:
        for ref in idautils.CodeRefsFrom(bb_end, True):
            if ref == bb.start_ea:
                return True
    return False


def find_data_reference_from_insn(insn: idaapi.insn_t, max_depth: int = 10) -> int:
    """search for data reference from instruction, return address of instruction if no reference exists"""
    depth = 0
    ea = insn.ea

    while True:
        data_refs = list(idautils.DataRefsFrom(ea))

        if len(data_refs) != 1:
            # break if no refs or more than one ref (assume nested pointers only have one data reference)
            break

        if ea == data_refs[0]:
            # break if circular reference
            break

        if not idaapi.is_mapped(data_refs[0]):
            # break if address is not mapped
            break

        depth += 1
        if depth > max_depth:
            # break if max depth
            break

        ea = data_refs[0]

    return ea


def get_function_blocks(f: idaapi.func_t) -> Iterator[idaapi.BasicBlock]:
    """yield basic blocks contained in specified function"""
    # leverage idaapi.FC_NOEXT flag to ignore useless external blocks referenced by the function
    for block in idaapi.FlowChart(f, flags=(idaapi.FC_PREDS | idaapi.FC_NOEXT)):
        yield block


def is_basic_block_return(bb: idaapi.BasicBlock) -> bool:
    """check if basic block is return block"""
    return bb.type == idaapi.fcb_ret


def has_sib(oper: idaapi.op_t) -> bool:
    # via: https://reverseengineering.stackexchange.com/a/14300
    return oper.specflag1 == 1
