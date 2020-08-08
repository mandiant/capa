import logging

from lancelot import (
    OPERAND_TYPE,
    PERMISSION_READ,
    OPERAND_TYPE_REGISTER,
    OPERAND_TYPE_IMMEDIATE,
    IMMEDIATE_OPERAND_VALUE,
    REGISTER_OPERAND_REGISTER,
)

from capa.features import ARCH_X32, ARCH_X64
from capa.features.insn import Number

logger = logging.getLogger(__name__)


# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40


def get_arch(ws):
    if ws.arch == "x32":
        return ARCH_X32
    elif ws.arch == "x64":
        return ARCH_X64
    else:
        raise ValueError("unexpected architecture")


def get_imports(ws):
    """caching accessor"""
    raise NotImplementedError()


def extract_insn_api_features(ws, insn):
    """parse API features from the given instruction."""
    raise NotImplementedError()


def extract_insn_number_features(ws, insn):
    """parse number features from the given instruction."""
    operands = insn.operands

    for oper in operands:
        if oper[OPERAND_TYPE] != OPERAND_TYPE_IMMEDIATE:
            continue

        v = oper[IMMEDIATE_OPERAND_VALUE]

        if ws.probe(v) & PERMISSION_READ:
            # v is a valid address
            # therefore, assume its not also a constant.
            continue

        if (
            insn.mnemonic == "add"
            and operands[0][OPERAND_TYPE] == OPERAND_TYPE_REGISTER
            and operands[0][REGISTER_OPERAND_REGISTER] == "esp"
        ):
            # skip things like:
            #
            #    .text:00401140                 call    sub_407E2B
            #    .text:00401145                 add     esp, 0Ch
            return

        yield Number(v), insn.address
        yield Number(v, arch=get_arch(ws)), insn.address


def derefs(ws, p):
    """
    recursively follow the given pointer, yielding the valid memory addresses along the way.
    useful when you may have a pointer to string, or pointer to pointer to string, etc.
    this is a "do what i mean" type of helper function.
    """
    raise NotImplementedError()


def read_bytes(ws, va):
    """
    read up to MAX_BYTES_FEATURE_SIZE from the given address.
    """
    raise NotImplementedError()


def extract_insn_bytes_features(ws, insn):
    """
    parse byte sequence features from the given instruction.
    """
    raise NotImplementedError()


def read_string(ws, va):
    raise NotImplementedError()


def extract_insn_string_features(ws, insn):
    """parse string features from the given instruction."""
    raise NotImplementedError()


def extract_insn_offset_features(ws, insn):
    """parse structure offset features from the given instruction."""
    raise NotImplementedError()


def is_security_cookie(ws, insn):
    """
    check if an instruction is related to security cookie checks
    """
    raise NotImplementedError()


def extract_insn_nzxor_characteristic_features(ws, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    raise NotImplementedError()


def extract_insn_mnemonic_features(ws, insn):
    """parse mnemonic features from the given instruction."""
    raise NotImplementedError()


def extract_insn_peb_access_characteristic_features(ws, insn):
    """
    parse peb access from the given function. fs:[0x30] on x86, gs:[0x60] on x64
    """
    raise NotImplementedError()


def extract_insn_segment_access_features(ws, insn):
    """ parse the instruction for access to fs or gs """
    raise NotImplementedError()


def extract_insn_cross_section_cflow(ws, insn):
    """
    inspect the instruction for a CALL or JMP that crosses section boundaries.
    """
    raise NotImplementedError()


# this is a feature that's most relevant at the function scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_calls_from(ws, insn):
    raise NotImplementedError()


# this is a feature that's most relevant at the function or basic block scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_indirect_call_characteristic_features(ws, insn):
    """
    extract indirect function call characteristic (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974
    """
    raise NotImplementedError()


_not_implemented = set([])


def extract_insn_features(ws, insn):
    for insn_handler in INSTRUCTION_HANDLERS:
        try:
            for feature, va in insn_handler(ws, insn):
                yield feature, va
        except NotImplementedError:
            if insn_handler.__name__ not in _not_implemented:
                logger.warning("not implemented: %s", insn_handler.__name__)
                _not_implemented.add(insn_handler.__name__)


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_string_features,
    extract_insn_bytes_features,
    extract_insn_offset_features,
    extract_insn_nzxor_characteristic_features,
    extract_insn_mnemonic_features,
    extract_insn_peb_access_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_insn_segment_access_features,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
)
