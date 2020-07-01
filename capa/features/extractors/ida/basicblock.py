import sys
import struct
import string
import pprint

import idautils
import idaapi
import idc

from capa.features.extractors.ida import helpers

from capa.features import Characteristic
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN


def _ida_get_printable_len(op):
    ''' Return string length if all operand bytes are ascii or utf16-le printable

        args:
            op (IDA op_t)
    '''
    op_val = helpers.mask_op_val(op)

    if op.dtype == idaapi.dt_byte:
        chars = struct.pack('<B', op_val)
    elif op.dtype == idaapi.dt_word:
        chars = struct.pack('<H', op_val)
    elif op.dtype == idaapi.dt_dword:
        chars = struct.pack('<I', op_val)
    elif op.dtype == idaapi.dt_qword:
        chars = struct.pack('<Q', op_val)
    else:
        raise ValueError('Unhandled operand data type 0x%x.' % op.dtype)

    def _is_printable_ascii(chars):
        if sys.version_info >= (3, 0):
            return all(c < 127 and chr(c) in string.printable for c in chars)
        else:
            return all(ord(c) < 127 and c in string.printable for c in chars)

    def _is_printable_utf16le(chars):
        if sys.version_info >= (3, 0):
            if all(c == 0x00 for c in chars[1::2]):
                return _is_printable_ascii(chars[::2])
        else:
            if all(c == '\x00' for c in chars[1::2]):
                return _is_printable_ascii(chars[::2])

    if _is_printable_ascii(chars):
        return idaapi.get_dtype_size(op.dtype)

    if _is_printable_utf16le(chars):
        return idaapi.get_dtype_size(op.dtype) / 2

    return 0


def _is_mov_imm_to_stack(insn):
    ''' verify instruction moves immediate onto stack

        args:
            insn (IDA insn_t)
    '''
    if insn.Op2.type != idaapi.o_imm:
        return False

    if not helpers.is_op_stack_var(insn.ea, 0):
        return False

    if not insn.get_canon_mnem().startswith('mov'):
        return False

    return True


def _ida_bb_contains_stackstring(f, bb):
    ''' check basic block for stackstring indicators

        true if basic block contains enough moves of constant bytes to the stack

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
    '''
    count = 0

    for insn in helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
        if _is_mov_imm_to_stack(insn):
            count += _ida_get_printable_len(insn.Op2)

        if count > MIN_STACKSTRING_LEN:
            return True

    return False


def extract_bb_stackstring(f, bb):
    ''' extract stackstring indicators from basic block

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
    '''
    if _ida_bb_contains_stackstring(f, bb):
        yield Characteristic('stack string'), bb.start_ea


def _ida_bb_contains_tight_loop(f, bb):
    ''' check basic block for stackstring indicators

        true if last instruction in basic block branches to basic block start

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
    '''
    bb_end = idc.prev_head(bb.end_ea)

    if bb.start_ea < bb_end:
        for ref in idautils.CodeRefsFrom(bb_end, True):
            if ref == bb.start_ea:
                return True

    return False


def extract_bb_tight_loop(f, bb):
    ''' extract tight loop indicators from a basic block

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
    '''
    if _ida_bb_contains_tight_loop(f, bb):
        yield Characteristic('tight loop'), bb.start_ea


def extract_features(f, bb):
    ''' extract basic block features

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
    '''
    yield BasicBlock(), bb.start_ea

    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, va in bb_handler(f, bb):
            yield feature, va


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_bb_stackstring,
)


def main():
    features = []

    for f in helpers.get_functions(ignore_thunks=True, ignore_libs=True):
        for bb in idaapi.FlowChart(f, flags=idaapi.FC_PREDS):
            features.extend(list(extract_features(f, bb)))

    pprint.pprint(features)


if __name__ == '__main__':
    main()
