import re
import string
import struct

from smda.common.SmdaReport import SmdaReport

import capa.features.extractors.helpers
from capa.features.insn import API, MAX_STRUCTURE_SIZE, Number, Offset, Mnemonic, OperandNumber, OperandOffset
from capa.features.common import MAX_BYTES_FEATURE_SIZE, THUNK_CHAIN_DEPTH_DELTA, Bytes, String, Characteristic

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40
PATTERN_HEXNUM = re.compile(r"[+\-] (?P<num>0x[a-fA-F0-9]+)")
PATTERN_SINGLENUM = re.compile(r"[+\-] (?P<num>[0-9])")


def extract_insn_api_features(f, bb, insn):
    """parse API features from the given instruction."""
    if insn.offset in f.apirefs:
        api_entry = f.apirefs[insn.offset]
        # reformat
        dll_name, api_name = api_entry.split("!")
        dll_name = dll_name.split(".")[0]
        dll_name = dll_name.lower()
        for name in capa.features.extractors.helpers.generate_symbols(dll_name, api_name):
            yield API(name), insn.offset
    elif insn.offset in f.outrefs:
        current_function = f
        current_instruction = insn
        for index in range(THUNK_CHAIN_DEPTH_DELTA):
            if current_function and len(current_function.outrefs[current_instruction.offset]) == 1:
                target = current_function.outrefs[current_instruction.offset][0]
                referenced_function = current_function.smda_report.getFunction(target)
                if referenced_function:
                    # TODO SMDA: implement this function for both jmp and call, checking if function has 1 instruction which refs an API
                    if referenced_function.isApiThunk():
                        api_entry = (
                            referenced_function.apirefs[target] if target in referenced_function.apirefs else None
                        )
                        if api_entry:
                            # reformat
                            dll_name, api_name = api_entry.split("!")
                            dll_name = dll_name.split(".")[0]
                            dll_name = dll_name.lower()
                            for name in capa.features.extractors.helpers.generate_symbols(dll_name, api_name):
                                yield API(name), insn.offset
                    elif referenced_function.num_instructions == 1 and referenced_function.num_outrefs == 1:
                        current_function = referenced_function
                        current_instruction = [i for i in referenced_function.getInstructions()][0]
                else:
                    return


def extract_insn_number_features(f, bb, insn):
    """parse number features from the given instruction."""
    # example:
    #
    #     push    3136B0h         ; dwControlCode
    operands = [o.strip() for o in insn.operands.split(",")]
    if insn.mnemonic == "add" and operands[0] in ["esp", "rsp"]:
        # skip things like:
        #
        #    .text:00401140                 call    sub_407E2B
        #    .text:00401145                 add     esp, 0Ch
        return
    for i, operand in enumerate(operands):
        try:
            # The result of bitwise operations is calculated as though carried out
            # in two’s complement with an infinite number of sign bits
            value = int(operand, 16) & ((1 << f.smda_report.bitness) - 1)
        except ValueError:
            continue
        else:
            yield Number(value), insn.offset
            yield OperandNumber(i, value), insn.offset

            if insn.mnemonic == "add" and 0 < value < MAX_STRUCTURE_SIZE:
                # for pattern like:
                #
                #     add eax, 0x10
                #
                # assume 0x10 is also an offset (imagine eax is a pointer).
                yield Offset(value), insn.offset
                yield OperandOffset(i, value), insn.offset


def read_bytes(smda_report, va, num_bytes=None):
    """
    read up to MAX_BYTES_FEATURE_SIZE from the given address.
    """

    rva = va - smda_report.base_addr
    if smda_report.buffer is None:
        raise ValueError("buffer is empty")
    buffer_end = len(smda_report.buffer)
    max_bytes = num_bytes if num_bytes is not None else MAX_BYTES_FEATURE_SIZE
    if rva + max_bytes > buffer_end:
        return smda_report.buffer[rva:]
    else:
        return smda_report.buffer[rva : rva + max_bytes]


def derefs(smda_report, p):
    """
    recursively follow the given pointer, yielding the valid memory addresses along the way.
    useful when you may have a pointer to string, or pointer to pointer to string, etc.

    this is a "do what i mean" type of helper function.

    based on the implementation in viv/insn.py
    """
    depth = 0
    while True:
        if not smda_report.isAddrWithinMemoryImage(p):
            return
        yield p

        bytes_ = read_bytes(smda_report, p, num_bytes=4)
        val = struct.unpack("I", bytes_)[0]

        # sanity: pointer points to self
        if val == p:
            return

        # sanity: avoid chains of pointers that are unreasonably deep
        depth += 1
        if depth > 10:
            return

        p = val


def extract_insn_bytes_features(f, bb, insn):
    """
    parse byte sequence features from the given instruction.
    example:
        #     push    offset iid_004118d4_IShellLinkA ; riid
    """
    for data_ref in insn.getDataRefs():
        for v in derefs(f.smda_report, data_ref):
            bytes_read = read_bytes(f.smda_report, v)
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
        for v in derefs(f.smda_report, data_ref):
            string_read = read_string(f.smda_report, v)
            if string_read:
                yield String(string_read.rstrip("\x00")), insn.offset


def extract_insn_offset_features(f, bb, insn):
    """parse structure offset features from the given instruction."""
    # examples:
    #
    #     mov eax, [esi + 4]
    #     mov eax, [esi + ecx + 16384]
    operands = [o.strip() for o in insn.operands.split(",")]
    for i, operand in enumerate(operands):
        if "esp" in operand or "ebp" in operand or "rbp" in operand:
            continue

        number = 0
        number_hex = re.search(PATTERN_HEXNUM, operand)
        number_int = re.search(PATTERN_SINGLENUM, operand)
        if number_hex:
            number = int(number_hex.group("num"), 16)
            number = -1 * number if number_hex.group().startswith("-") else number
        elif number_int:
            number = int(number_int.group("num"))
            number = -1 * number if number_int.group().startswith("-") else number

        if "ptr" not in operand:
            if (
                insn.mnemonic == "lea"
                and i == 1
                and (operand.count("+") + operand.count("-")) == 1
                and operand.count("*") == 0
            ):
                # for pattern like:
                #
                #     lea eax, [ebx + 1]
                #
                # assume 1 is also an offset (imagine ebx is a zero register).
                yield Number(number), insn.offset
                yield OperandNumber(i, number), insn.offset

            continue

        yield Offset(number), insn.offset
        yield OperandOffset(i, number), insn.offset


def is_security_cookie(f, bb, insn):
    """
    check if an instruction is related to security cookie checks
    """
    # security cookie check should use SP or BP
    operands = [o.strip() for o in insn.operands.split(",")]
    if operands[1] not in ["esp", "ebp", "rsp", "rbp"]:
        return False
    for index, block in enumerate(f.getBlocks()):
        # expect security cookie init in first basic block within first bytes (instructions)
        block_instructions = [i for i in block.getInstructions()]
        if index == 0 and insn.offset < (block_instructions[0].offset + SECURITY_COOKIE_BYTES_DELTA):
            return True
        # ... or within last bytes (instructions) before a return
        if block_instructions[-1].mnemonic.startswith("ret") and insn.offset > (
            block_instructions[-1].offset - SECURITY_COOKIE_BYTES_DELTA
        ):
            return True
    return False


def extract_insn_nzxor_characteristic_features(f, bb, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """

    if insn.mnemonic not in ("xor", "xorpd", "xorps", "pxor"):
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


def extract_insn_obfs_call_plus_5_characteristic_features(f, bb, insn):
    """
    parse call $+5 instruction from the given instruction.
    """
    if insn.mnemonic != "call":
        return

    if not insn.operands.startswith("0x"):
        return

    if int(insn.operands, 16) == insn.offset + 5:
        yield Characteristic("call $+5"), insn.offset


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
    """parse the instruction for access to fs or gs"""
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

        smda_report = insn.smda_function.smda_report
        if insn.offset in f.outrefs:
            for target in f.outrefs[insn.offset]:
                if smda_report.getSection(insn.offset) != smda_report.getSection(target):
                    yield Characteristic("cross section flow"), insn.offset
        elif insn.operands.startswith("0x"):
            target = int(insn.operands, 16)
            if smda_report.getSection(insn.offset) != smda_report.getSection(target):
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
    if insn.offset in f.apirefs:
        yield Characteristic("calls from"), insn.offset


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
      Tuple[Feature, int]: the features and their location found in this insn.
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
    extract_insn_obfs_call_plus_5_characteristic_features,
    extract_insn_peb_access_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_insn_segment_access_features,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
)
