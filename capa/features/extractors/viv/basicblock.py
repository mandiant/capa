import struct
import string

import envi
import vivisect.const

from capa.features import Characteristic
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN


def interface_extract_basic_block_XXX(f, bb):
    '''
    parse features from the given basic block.

    args:
      f (viv_utils.Function): the function to process.
      bb (viv_utils.BasicBlock): the basic block to process.

    yields:
      (Feature, int): the feature and the address at which its found.
    '''
    yield NotImplementedError('feature'), NotImplementedError('virtual address')


def _bb_has_tight_loop(f, bb):
    '''
    parse tight loops, true if last instruction in basic block branches to bb start
    '''
    if len(bb.instructions) > 0:
        for bva, bflags in bb.instructions[-1].getBranches():
            if bflags & vivisect.envi.BR_COND:
                if bva == bb.va:
                    return True

    return False


def extract_bb_tight_loop(f, bb):
    ''' check basic block for tight loop indicators '''
    if _bb_has_tight_loop(f, bb):
        yield Characteristic('tight loop'), bb.va


def _bb_has_stackstring(f, bb):
    '''
    extract potential stackstring creation, using the following heuristics:
      - basic block contains enough moves of constant bytes to the stack
    '''
    count = 0
    for instr in bb.instructions:
        if is_mov_imm_to_stack(instr):
            # add number of operand bytes
            src = instr.getOperands()[1]
            count += get_printable_len(src)
        if count > MIN_STACKSTRING_LEN:
            return True

    return False


def extract_stackstring(f, bb):
    ''' check basic block for stackstring indicators '''
    if _bb_has_stackstring(f, bb):
        yield Characteristic('stack string'), bb.va


def is_mov_imm_to_stack(instr):
    '''
    Return if instruction moves immediate onto stack
    '''
    if not instr.mnem.startswith('mov'):
        return False

    try:
        dst, src = instr.getOperands()
    except ValueError:
        # not two operands
        return False

    if not src.isImmed():
        return False

    # TODO what about 64-bit operands?
    if not isinstance(dst, envi.archs.i386.disasm.i386SibOper) and \
            not isinstance(dst, envi.archs.i386.disasm.i386RegMemOper):
        return False

    if not dst.reg:
        return False

    rname = dst._dis_regctx.getRegisterName(dst.reg)
    if rname not in ['ebp', 'rbp', 'esp', 'rsp']:
        return False

    return True


def get_printable_len(oper):
    '''
    Return string length if all operand bytes are ascii or utf16-le printable
    '''
    if oper.tsize == 1:
        chars = struct.pack('<B', oper.imm)
    elif oper.tsize == 2:
        chars = struct.pack('<H', oper.imm)
    elif oper.tsize == 4:
        chars = struct.pack('<I', oper.imm)
    elif oper.tsize == 8:
        chars = struct.pack('<Q', oper.imm)
    if is_printable_ascii(chars):
        return oper.tsize
    if is_printable_utf16le(chars):
        return oper.tsize / 2
    return 0


def is_printable_ascii(chars):
    return all(ord(c) < 127 and c in string.printable for c in chars)


def is_printable_utf16le(chars):
    if all(c == '\x00' for c in chars[1::2]):
        return is_printable_ascii(chars[::2])


def extract_features(f, bb):
    '''
    extract features from the given basic block.

    args:
      f (viv_utils.Function): the function from which to extract features
      bb (viv_utils.BasicBlock): the basic block to process.

    yields:
      Feature, set[VA]: the features and their location found in this basic block.
    '''
    yield BasicBlock(), bb.va
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, va in bb_handler(f, bb):
            yield feature, va


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_stackstring,
)
