# Copyright 2020 Google LLC
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

import functools
from typing import Any, Iterator, Optional

import idc
import idaapi
import ida_nalt
import idautils
import ida_bytes
import ida_funcs
import ida_segment
from ida_domain import Database
from ida_domain.functions import FunctionFlags

from capa.features.address import AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import FunctionHandle


def find_byte_sequence(db: Database, start: int, end: int, seq: bytes) -> Iterator[int]:
    """yield all ea of a given byte sequence

    args:
        db: IDA Domain Database handle
        start: min virtual address
        end: max virtual address
        seq: bytes to search e.g. b"\x01\x03"
    """
    for match in db.bytes.find_binary_sequence(seq, start, end):
        yield match


def get_functions(
    db: Database,
    start: Optional[int] = None,
    end: Optional[int] = None,
    skip_thunks: bool = False,
    skip_libs: bool = False,
) -> Iterator[FunctionHandle]:
    """get functions, range optional

    args:
        db: IDA Domain Database handle
        start: min virtual address
        end: max virtual address
        skip_thunks: skip thunk functions
        skip_libs: skip library functions
    """
    if start is not None and end is not None:
        funcs = db.functions.get_between(start, end)
    else:
        funcs = db.functions.get_all()

    for f in funcs:
        flags = db.functions.get_flags(f)
        if skip_thunks and (flags & FunctionFlags.THUNK):
            continue
        if skip_libs and (flags & FunctionFlags.LIB):
            continue
        yield FunctionHandle(address=AbsoluteVirtualAddress(f.start_ea), inner=f)


def get_segments(db: Database, skip_header_segments: bool = False):
    """get list of segments (sections) in the binary image

    args:
        db: IDA Domain Database handle
        skip_header_segments: IDA may load header segments - skip if set
    """
    for seg in db.segments.get_all():
        if skip_header_segments and seg.is_header_segm():
            continue
        yield seg


def get_segment_buffer(db: Database, seg) -> bytes:
    """return bytes stored in a given segment

    args:
        db: IDA Domain Database handle
        seg: segment object
    """
    sz = seg.end_ea - seg.start_ea

    # decrease buffer size until IDA is able to read bytes from the segment
    while sz > 0:
        buff = db.bytes.get_bytes_at(seg.start_ea, sz)
        if buff:
            return buff
        sz -= 0x1000

    return b""


def inspect_import(imports, library, ea, function, ordinal):
    if function and function.startswith("__imp_"):
        # handle mangled PE imports
        function = function[len("__imp_") :]

    if function and "@@" in function:
        # handle mangled ELF imports, like "fopen@@glibc_2.2.5"
        function, _, _ = function.partition("@@")

    imports[ea] = (library.lower(), function, ordinal)
    return True


def get_file_imports(db: Database) -> dict[int, tuple[str, str, int]]:
    """get file imports

    Note: import enumeration has no Domain API equivalent, using SDK fallback.

    args:
        db: IDA Domain Database handle (unused, kept for API consistency)
    """
    imports: dict[int, tuple[str, str, int]] = {}

    for idx in range(idaapi.get_import_module_qty()):
        library = idaapi.get_import_module_name(idx)

        if not library:
            continue

        # IDA uses section names for the library of ELF imports, like ".dynsym".
        # These are not useful to us, we may need to expand this list over time
        # TODO(williballenthin): find all section names used by IDA
        # https://github.com/mandiant/capa/issues/1419
        if library == ".dynsym":
            library = ""

        cb = functools.partial(inspect_import, imports, library)
        idaapi.enum_import_names(idx, cb)

    return imports


def get_file_externs(db: Database) -> dict[int, tuple[str, str, int]]:
    """get extern functions

    args:
        db: IDA Domain Database handle
    """
    externs = {}

    for seg in get_segments(db, skip_header_segments=True):
        if seg.type != ida_segment.SEG_XTRN:
            continue

        for f in db.functions.get_between(seg.start_ea, seg.end_ea):
            name = db.functions.get_name(f)
            externs[f.start_ea] = ("", name, -1)

    return externs


def get_instructions_in_range(db: Database, start: int, end: int) -> Iterator[idaapi.insn_t]:
    """yield instructions in range

    args:
        db: IDA Domain Database handle
        start: virtual address (inclusive)
        end: virtual address (exclusive)
    """
    for head in db.heads.get_between(start, end):
        insn = db.instructions.get_at(head)
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


def read_bytes_at(db: Database, ea: int, count: int) -> bytes:
    """read bytes at address

    args:
        db: IDA Domain Database handle
        ea: effective address
        count: number of bytes to read
    """
    if not db.bytes.is_value_initialized_at(ea):
        return b""

    seg = db.segments.get_at(ea)
    if seg is None:
        return b""

    if ea + count > seg.end_ea:
        return db.bytes.get_bytes_at(ea, seg.end_ea - ea) or b""
    else:
        return db.bytes.get_bytes_at(ea, count) or b""


def find_string_at(db: Database, ea: int, min_: int = 4) -> str:
    """check if string exists at a given virtual address

    Note: Uses SDK fallback as Domain API get_string_at only works for
    addresses where IDA has already identified a string.

    args:
        db: IDA Domain Database handle (unused, kept for API consistency)
        ea: effective address
        min_: minimum string length
    """
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


def get_op_phrase_info(op: idaapi.op_t) -> dict:
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
    return any(
        op.reg == idautils.procregs.sp.reg and is_op_write(insn, op)
        for op in get_insn_ops(insn, target_ops=(idaapi.o_reg,))
    )


def is_bp_modified(insn: idaapi.insn_t) -> bool:
    """check if instruction modifies BP, EBP, RBP"""
    return any(
        op.reg == idautils.procregs.bp.reg and is_op_write(insn, op)
        for op in get_insn_ops(insn, target_ops=(idaapi.o_reg,))
    )


def is_frame_register(reg: int) -> bool:
    """check if register is sp or bp"""
    return reg in (idautils.procregs.sp.reg, idautils.procregs.bp.reg)


def get_insn_ops(insn: idaapi.insn_t, target_ops: Optional[tuple[Any]] = None) -> idaapi.op_t:
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


def is_function_recursive(db: Database, f: idaapi.func_t) -> bool:
    """check if function is recursive

    args:
        db: IDA Domain Database handle
        f: function object
    """
    for ref in db.xrefs.code_refs_to_ea(f.start_ea):
        if f.contains(ref):
            return True
    return False


def is_basic_block_tight_loop(db: Database, bb: idaapi.BasicBlock) -> bool:
    """check basic block loops to self

    args:
        db: IDA Domain Database handle
        bb: basic block object

    true if last instruction in basic block branches to basic block start
    """
    bb_end = db.heads.get_previous(bb.end_ea)
    if bb_end is None:
        return False
    if bb.start_ea < bb_end:
        for ref in db.xrefs.code_refs_from_ea(bb_end):
            if ref == bb.start_ea:
                return True
    return False


def find_data_reference_from_insn(db: Database, insn: idaapi.insn_t, max_depth: int = 10) -> int:
    """search for data reference from instruction, return address of instruction if no reference exists

    args:
        db: IDA Domain Database handle
        insn: instruction object
        max_depth: maximum depth to follow references
    """
    depth = 0
    ea = insn.ea

    while True:
        data_refs = list(db.xrefs.data_refs_from_ea(ea))

        if len(data_refs) != 1:
            # break if no refs or more than one ref (assume nested pointers only have one data reference)
            break

        if ea == data_refs[0]:
            # break if circular reference
            break

        if not db.is_valid_ea(data_refs[0]):
            # break if address is not mapped
            break

        depth += 1
        if depth > max_depth:
            # break if max depth
            break

        ea = data_refs[0]

    return ea


def get_function_blocks(db: Database, f: idaapi.func_t) -> Iterator[idaapi.BasicBlock]:
    """yield basic blocks contained in specified function

    args:
        db: IDA Domain Database handle
        f: function object
    """
    # leverage idaapi.FC_NOEXT flag to ignore useless external blocks referenced by the function
    flowchart = db.functions.get_flowchart(f, flags=(idaapi.FC_PREDS | idaapi.FC_NOEXT))
    yield from flowchart


def is_basic_block_return(bb: idaapi.BasicBlock) -> bool:
    """check if basic block is return block"""
    return bb.type == idaapi.fcb_ret


def has_sib(oper: idaapi.op_t) -> bool:
    # via: https://reverseengineering.stackexchange.com/a/14300
    return oper.specflag1 == 1


def find_alternative_names(cmt: str):
    for line in cmt.split("\n"):
        if line.startswith("Alternative name is '") and line.endswith("'"):
            name = line[len("Alternative name is '") : -1]  # Extract name between quotes
            yield name


def get_function_alternative_names(db: Database, fva: int):
    """Get all alternative names for an address.

    args:
        db: IDA Domain Database handle
        fva: function virtual address
    """
    cmt_info = db.comments.get_at(fva)
    cmt = cmt_info.comment if cmt_info else ""
    yield from find_alternative_names(cmt)
    f = db.functions.get_at(fva)
    if f:
        func_cmt = db.functions.get_comment(f, False)
        yield from find_alternative_names(func_cmt or "")
