import logging

import pefile

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

from lancelot import (
    OPERAND_TYPE,
    PERMISSION_READ,
    MEMORY_OPERAND_BASE,
    MEMORY_OPERAND_DISP,
    OPERAND_TYPE_MEMORY,
    OPERAND_TYPE_REGISTER,
    OPERAND_TYPE_IMMEDIATE,
    IMMEDIATE_OPERAND_VALUE,
    REGISTER_OPERAND_REGISTER,
    IMMEDIATE_OPERAND_IS_RELATIVE,
)

import capa.features.extractors.helpers
from capa.features import ARCH_X32, ARCH_X64
from capa.features.insn import Number, Offset

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


@lru_cache
def get_imports(xtor):
    pe = pefile.PE(data=xtor.buf)

    imports = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        libname = entry.dll.decode("ascii").lower().partition(".")[0]
        for imp in entry.imports:
            if imp.ordinal:
                imports[imp.address] = "%s.#%s" % (libname, imp.ordinal)
            else:
                impname = imp.name.decode("ascii")
                imports[imp.address] = "%s.%s" % (libname, impname)
    return imports


@lru_cache
def get_thunks(xtor):
    thunks = {}
    for va in xtor.ws.get_functions():
        try:
            insn = xtor.ws.read_insn(va)
        except ValueError:
            continue

        if insn.mnemonic != "jmp":
            continue

        op0 = insn.operands[0]

        if op0[OPERAND_TYPE] == OPERAND_TYPE_MEMORY:
            target = op0[MEMORY_OPERAND_DISP]

            # direct, x64, rip relative
            # 180020570 FF 25 DA 83 05 00       jmp     cs:RtlCaptureContext_0
            if op0[MEMORY_OPERAND_BASE] == "rip":
                target = op0[MEMORY_OPERAND_DISP] + insn.address + insn.length

            # direct, x32
            # mimikatz:.text:0046AE12 FF 25 54 30 47 00  jmp     ds:__imp_LsaQueryInformationPolicy
            elif op0[MEMORY_OPERAND_BASE] == None:
                target = op0[MEMORY_OPERAND_DISP]

            else:
                continue

            imports = get_imports(xtor)
            if target not in imports:
                continue

            thunks[va] = imports[target]
            continue

    return thunks


def extract_insn_api_features(xtor, insn):
    """parse API features from the given instruction."""

    if insn.mnemonic != "call":
        return

    op0 = insn.operands[0]

    if op0[OPERAND_TYPE] == OPERAND_TYPE_MEMORY:

        # call direct, x64
        # rip relative
        # kernel32-64:180001041    call    cs:__imp_RtlVirtualUnwind_0
        if op0[MEMORY_OPERAND_BASE] == "rip":
            target = op0[MEMORY_OPERAND_DISP] + insn.address + insn.length

        # call direct, x32
        # mimikatz:0x403BD3  call    ds:CryptAcquireContextW
        elif op0[MEMORY_OPERAND_BASE] == None:
            target = op0[MEMORY_OPERAND_DISP]

        else:
            return

        imports = get_imports(xtor)
        if target in imports:
            for feature, va in capa.features.extractors.helpers.generate_api_features(imports[target], insn.address):
                yield feature, va

    # call via thunk
    # mimikatz:0x455A41  call    LsaQueryInformationPolicy
    elif op0[OPERAND_TYPE] == OPERAND_TYPE_IMMEDIATE and op0[IMMEDIATE_OPERAND_IS_RELATIVE]:
        target = op0[IMMEDIATE_OPERAND_VALUE] + insn.address + insn.length
        thunks = get_thunks(xtor)
        if target in thunks:
            for feature, va in capa.features.extractors.helpers.generate_api_features(thunks[target], insn.address):
                yield feature, va

    # call on x64

    raise NotImplementedError()


def extract_insn_number_features(xtor, insn):
    """parse number features from the given instruction."""
    operands = insn.operands

    for oper in operands:
        if oper[OPERAND_TYPE] != OPERAND_TYPE_IMMEDIATE:
            continue

        v = oper[IMMEDIATE_OPERAND_VALUE]

        if xtor.ws.probe(v) & PERMISSION_READ:
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
        yield Number(v, arch=get_arch(xtor.ws)), insn.address


def extract_insn_offset_features(xtor, insn):
    """parse structure offset features from the given instruction."""
    operands = insn.operands

    for oper in operands:
        if oper[OPERAND_TYPE] != OPERAND_TYPE_MEMORY:
            continue

        if oper[MEMORY_OPERAND_BASE] in ("esp", "ebp", "rbp"):
            continue

        # lancelot provides `None` when the displacement is not present.
        v = oper[MEMORY_OPERAND_DISP] or 0

        yield Offset(v), insn.address
        yield Offset(v, arch=get_arch(xtor.ws)), insn.address


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


def extract_insn_bytes_features(xtor, insn):
    """
    parse byte sequence features from the given instruction.
    """
    raise NotImplementedError()


def read_string(ws, va):
    raise NotImplementedError()


def extract_insn_string_features(xtor, insn):
    """parse string features from the given instruction."""
    raise NotImplementedError()


def is_security_cookie(ws, insn):
    """
    check if an instruction is related to security cookie checks
    """
    raise NotImplementedError()


def extract_insn_nzxor_characteristic_features(xtor, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    raise NotImplementedError()


def extract_insn_mnemonic_features(xtor, insn):
    """parse mnemonic features from the given instruction."""
    raise NotImplementedError()


def extract_insn_peb_access_characteristic_features(xtor, insn):
    """
    parse peb access from the given function. fs:[0x30] on x86, gs:[0x60] on x64
    """
    raise NotImplementedError()


def extract_insn_segment_access_features(xtor, insn):
    """ parse the instruction for access to fs or gs """
    raise NotImplementedError()


def extract_insn_cross_section_cflow(xtor, insn):
    """
    inspect the instruction for a CALL or JMP that crosses section boundaries.
    """
    raise NotImplementedError()


# this is a feature that's most relevant at the function scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_calls_from(xtor, insn):
    raise NotImplementedError()


# this is a feature that's most relevant at the function or basic block scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_indirect_call_characteristic_features(xtor, insn):
    """
    extract indirect function call characteristic (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974
    """
    raise NotImplementedError()


_not_implemented = set([])


def extract_insn_features(xtor, insn):
    for insn_handler in INSTRUCTION_HANDLERS:
        try:
            for feature, va in insn_handler(xtor, insn):
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
