import re
import string

from smda.common.SmdaReport import SmdaReport

import capa.features.extractors.helpers
from capa.features import (
    ARCH_X32,
    ARCH_X64,
    MAX_BYTES_FEATURE_SIZE,
    THUNK_CHAIN_DEPTH_DELTA,
    Bytes,
    String,
    Characteristic,
)
from capa.features.insn import API, Number, Offset, Mnemonic

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40
PATTERN_HEXNUM = re.compile(r"[+\-] (?P<num>0x[a-fA-F0-9]+)")
PATTERN_SINGLENUM = re.compile(r"[+\-] (?P<num>[0-9])")


def get_arch(smda_report):
    if smda_report.architecture == "intel":
        if smda_report.bitness == 32:
            return ARCH_X32
        elif smda_report.bitness == 64:
            return ARCH_X64
    else:
        raise NotImplementedError


def interface_extract_instruction_XXX(f, bb, insn):
    """
    parse features from the given instruction.

    args:
      f (smda.common.SmdaFunction): the function to process.
      bb (smda.common.SmdaBasicBlock): the basic block to process.
      insn (smda.common.SmdaInstruction): the instruction to process.

    yields:
      (Feature, int): the feature and the address at which its found.
    """
    yield NotImplementedError("feature"), NotImplementedError("virtual address")


def extract_insn_api_features(f, bb, insn):
    """parse API features from the given instruction."""
    if insn.offset in f.apirefs:
        api_entry = f.apirefs[insn.offset]
        # reformat
        dll_name, api_name = api_entry.split("!")
        dll_name = dll_name.split(".")[0]
        for name in capa.features.extractors.helpers.generate_symbols(dll_name, api_name):
            yield API(name), insn.offset


def extract_insn_number_features(f, bb, insn):
    """parse number features from the given instruction."""
    # example:
    #
    #     push    3136B0h         ; dwControlCode
    operands = [o.strip() for o in insn.operands.split(",")]
    for operand in operands:
        if insn.mnemonic == "add" and operands[0] in ["esp", "rsp"]:
            # skip things like:
            #
            #    .text:00401140                 call    sub_407E2B
            #    .text:00401145                 add     esp, 0Ch
            return
        try:
            yield Number(int(operand, 16)), insn.offset
        except:
            return


def read_bytes(smda_report, va, num_bytes=None):
    """
    read up to MAX_BYTES_FEATURE_SIZE from the given address.
    """

    rva = va - smda_report.base_addr
    if smda_report.buffer is None:
        return
    buffer_end = len(smda_report.buffer)
    max_bytes = num_bytes if num_bytes is not None else MAX_BYTES_FEATURE_SIZE
    if rva + max_bytes > buffer_end:
        return smda_report.buffer[rva:]
    else:
        return smda_report.buffer[rva : rva + max_bytes]


def extract_insn_bytes_features(f, bb, insn):
    """
    parse byte sequence features from the given instruction.
    example:
        #     push    offset iid_004118d4_IShellLinkA ; riid
    """
    for data_ref in insn.getDataRefs():
        bytes_read = read_bytes(f.smda_report, data_ref)
        if bytes_read is None:
            continue
        if capa.features.extractors.helpers.all_zeros(bytes_read):
            continue
        yield Bytes(bytes_read), insn.offset


def detect_ascii_len(smda_report, offset):
    if smda_report.buffer is None:
        return 0
    ascii_len = 0
    rva = offset - smda_report.base_addr
    char = smda_report.buffer[rva]
    while char < 127 and chr(char) in string.printable:
        ascii_len += 1
        rva += 1
        char = smda_report.buffer[rva]
    if char == 0:
        return ascii_len
    return 0


def detect_unicode_len(smda_report, offset):
    if smda_report.buffer is None:
        return 0
    unicode_len = 0
    rva = offset - smda_report.base_addr
    char = smda_report.buffer[rva]
    second_char = smda_report.buffer[rva + 1]
    while char < 127 and chr(char) in string.printable and second_char == 0:
        unicode_len += 2
        rva += 2
        char = smda_report.buffer[rva]
        second_char = smda_report.buffer[rva + 1]
    if char == 0 and second_char == 0:
        return unicode_len
    return 0


def read_string(smda_report, offset):
    alen = detect_ascii_len(smda_report, offset)
    if alen > 1:
        return read_bytes(smda_report, offset, alen).decode("utf-8")
    ulen = detect_unicode_len(smda_report, offset)
    if ulen > 2:
        return read_bytes(smda_report, offset, ulen).decode("utf-16")


def extract_insn_string_features(f, bb, insn):
    """parse string features from the given instruction."""
    # example:
    #
    #     push    offset aAcr     ; "ACR  > "
    for data_ref in insn.getDataRefs():
        string_read = read_string(f.smda_report, data_ref)
        if string_read:
            yield String(string_read.rstrip("\x00")), insn.offset


def extract_insn_offset_features(f, bb, insn):
    """parse structure offset features from the given instruction."""
    # examples:
    #
    #     mov eax, [esi + 4]
    #     mov eax, [esi + ecx + 16384]
    operands = [o.strip() for o in insn.operands.split(",")]
    for operand in operands:
        number = None
        number_hex = re.search(PATTERN_HEXNUM, operand)
        number_int = re.search(PATTERN_SINGLENUM, operand)
        if number_hex:
            number = int(number_hex.group("num"), 16)
            number = -1 * number if number_hex.group().startswith("-") else number
        elif number_int:
            number = int(number_int.group("num"))
            number = -1 * number if number_int.group().startswith("-") else number
        if not operand.startswith("0") and number is not None:
            yield Offset(number), insn.offset


def is_security_cookie(f, bb, insn):
    """
    check if an instruction is related to security cookie checks
    """
    # security cookie check should use SP or BP
    operands = [o.strip() for o in insn.operands.split(",")]
    if operands[0] not in ["esp", "ebp", "rsp", "rbp"]:
        return False
    for index, block in enumerate(f.getBlocks()):
        # expect security cookie init in first basic block within first bytes (instructions)
        if index == 0 and insn.offset < (block[0].offset + SECURITY_COOKIE_BYTES_DELTA):
            return True
        # ... or within last bytes (instructions) before a return
        if block[-1].mnemonic.startswith("ret") and insn.offset > (block[-1].offset - SECURITY_COOKIE_BYTES_DELTA):
            return True
    return False


def extract_insn_nzxor_characteristic_features(f, bb, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """

    if insn.mnemonic != "xor":
        return

    operands = [o.strip() for o in insn.operands.split(",")]
    if operands[0] == operands[1]:
        return

    if is_security_cookie(f, bb, insn):
        return

    yield Characteristic("nzxor"), insn.offset


def extract_insn_mnemonic_features(f, bb, insn):
    """parse mnemonic features from the given instruction."""
    yield Mnemonic(insn.mnemonic), insn.offset


def extract_insn_peb_access_characteristic_features(f, bb, insn):
    """
    parse peb access from the given function. fs:[0x30] on x86, gs:[0x60] on x64
    """

    if insn.mnemonic not in ["push", "mov"]:
        return

    operands = [o.strip() for o in insn.operands.split(",")]
    for operand in operands:
        if "fs:" in operand and "0x30" in operand:
            yield Characteristic("peb access"), insn.offset
        elif "gs:" in operand and "0x60" in operand:
            yield Characteristic("peb access"), insn.offset


def extract_insn_segment_access_features(f, bb, insn):
    """ parse the instruction for access to fs or gs """
    operands = [o.strip() for o in insn.operands.split(",")]
    for operand in operands:
        if "fs:" in operand:
            yield Characteristic("fs access"), insn.offset
        elif "gs:" in operand:
            yield Characteristic("gs access"), insn.offset


def extract_insn_cross_section_cflow(f, bb, insn):
    """
    inspect the instruction for a CALL or JMP that crosses section boundaries.
    """
    if insn.mnemonic in ["call", "jmp"]:
        if insn.offset in f.apirefs:
            return

        if insn.offset in f.outrefs:
            for target in f.outrefs[insn.offset]:
                if not insn.smda_function.smda_report.isAddrWithinMemoryImage(target):
                    yield Characteristic("cross section flow"), insn.offset
        elif insn.operands.startswith("0x"):
            target = int(insn.operands, 16)
            if not insn.smda_function.smda_report.isAddrWithinMemoryImage(target):
                yield Characteristic("cross section flow"), insn.offset


# this is a feature that's most relevant at the function scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_calls_from(f, bb, insn):
    if insn.mnemonic != "call":
        return

    if insn.offset in f.outrefs:
        for outref in f.outrefs[insn.offset]:
            yield Characteristic("calls from"), outref

            if outref == f.offset:
                # if we found a jump target and it's the function address
                # mark as recursive
                yield Characteristic("recursive call"), outref


# this is a feature that's most relevant at the function or basic block scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_indirect_call_characteristic_features(f, bb, insn):
    """
    extract indirect function call characteristic (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974
    """
    if insn.mnemonic != "call":
        return
    if insn.operands.startswith("0x"):
        return False
    if "qword ptr" in insn.operands and "rip" in insn.operands:
        return False
    if insn.operands.startswith("dword ptr [0x"):
        return False
    # call edx
    # call dword ptr [eax+50h]
    # call qword ptr [rsp+78h]
    yield Characteristic("indirect call"), insn.offset


def extract_features(f, bb, insn):
    """
    extract features from the given insn.

    args:
      f (smda.common.SmdaFunction): the function to process.
      bb (smda.common.SmdaBasicBlock): the basic block to process.
      insn (smda.common.SmdaInstruction): the instruction to process.

    yields:
      Feature, set[VA]: the features and their location found in this insn.
    """
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature, va in insn_handler(f, bb, insn):
            yield feature, va


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
