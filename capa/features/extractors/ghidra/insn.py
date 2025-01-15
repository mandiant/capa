# Copyright 2023 Google LLC
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

from typing import Any, Iterator

import ghidra
from ghidra.program.model.lang import OperandType
from ghidra.program.model.block import SimpleBlockModel

import capa.features.extractors.helpers
import capa.features.extractors.ghidra.helpers
from capa.features.insn import API, MAX_STRUCTURE_SIZE, Number, Offset, Mnemonic, OperandNumber, OperandOffset
from capa.features.common import MAX_BYTES_FEATURE_SIZE, Bytes, String, Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40


OPERAND_TYPE_DYNAMIC_ADDRESS = OperandType.DYNAMIC | OperandType.ADDRESS


def get_imports(ctx: dict[str, Any]) -> dict[int, Any]:
    """Populate the import cache for this context"""
    if "imports_cache" not in ctx:
        ctx["imports_cache"] = capa.features.extractors.ghidra.helpers.get_file_imports()
    return ctx["imports_cache"]


def get_externs(ctx: dict[str, Any]) -> dict[int, Any]:
    """Populate the externs cache for this context"""
    if "externs_cache" not in ctx:
        ctx["externs_cache"] = capa.features.extractors.ghidra.helpers.get_file_externs()
    return ctx["externs_cache"]


def get_fakes(ctx: dict[str, Any]) -> dict[int, Any]:
    """Populate the fake import addrs cache for this context"""
    if "fakes_cache" not in ctx:
        ctx["fakes_cache"] = capa.features.extractors.ghidra.helpers.map_fake_import_addrs()
    return ctx["fakes_cache"]


def check_for_api_call(
    insn, externs: dict[int, Any], fakes: dict[int, Any], imports: dict[int, Any], imp_or_ex: bool
) -> Iterator[Any]:
    """check instruction for API call

    params:
        externs - external library functions cache
        fakes - mapped fake import addresses cache
        imports - imported functions cache
        imp_or_ex - flag to check imports or externs

    yields:
        matched api calls
    """
    info = ()
    funcs = imports if imp_or_ex else externs

    # assume only CALLs or JMPs are passed
    ref_type = insn.getOperandType(0)
    addr_data = OperandType.ADDRESS | OperandType.DATA  # needs dereferencing
    addr_code = OperandType.ADDRESS | OperandType.CODE  # needs dereferencing

    if OperandType.isRegister(ref_type):
        if OperandType.isAddress(ref_type):
            # If it's an address in a register, check the mapped fake addrs
            # since they're dereferenced to their fake addrs
            op_ref = insn.getAddress(0).getOffset()
            ref = fakes.get(op_ref)  # obtain the real addr
            if not ref:
                return
        else:
            return
    elif ref_type in (addr_data, addr_code) or (OperandType.isIndirect(ref_type) and OperandType.isAddress(ref_type)):
        # we must dereference and check if the addr is a pointer to an api function
        addr_ref = capa.features.extractors.ghidra.helpers.dereference_ptr(insn)
        if not capa.features.extractors.ghidra.helpers.check_addr_for_api(addr_ref, fakes, imports, externs):
            return
        ref = addr_ref.getOffset()
    elif ref_type == OPERAND_TYPE_DYNAMIC_ADDRESS or ref_type == OperandType.DYNAMIC:
        return  # cannot resolve dynamics statically
    else:
        # pure address does not need to get dereferenced/ handled
        addr_ref = insn.getAddress(0)
        if not addr_ref:
            # If it returned null, it was an indirect
            # that had no address reference.
            # This check is faster than checking for (indirect and not address)
            return
        if not capa.features.extractors.ghidra.helpers.check_addr_for_api(addr_ref, fakes, imports, externs):
            return
        ref = addr_ref.getOffset()

    if isinstance(ref, list):  # ref from REG | ADDR
        for r in ref:
            info = funcs.get(r)  # type: ignore
            if info:
                yield info
    else:
        info = funcs.get(ref)  # type: ignore
        if info:
            yield info


def extract_insn_api_features(fh: FunctionHandle, bb: BBHandle, ih: InsnHandle) -> Iterator[tuple[Feature, Address]]:
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    if not capa.features.extractors.ghidra.helpers.is_call_or_jmp(insn):
        return

    externs = get_externs(fh.ctx)
    fakes = get_fakes(fh.ctx)
    imports = get_imports(fh.ctx)

    # check calls to imported functions
    for api in check_for_api_call(insn, externs, fakes, imports, True):
        for imp in api:
            yield API(imp), ih.address

    # check calls to extern functions
    for api in check_for_api_call(insn, externs, fakes, imports, False):
        for ext in api:
            yield API(ext), ih.address


def extract_insn_number_features(fh: FunctionHandle, bb: BBHandle, ih: InsnHandle) -> Iterator[tuple[Feature, Address]]:
    """
    parse instruction number features
    example:
        push    3136B0h         ; dwControlCode
    """
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    if insn.getMnemonicString().startswith("RET"):
        # skip things like:
        #   .text:0042250E retn 8
        return

    if capa.features.extractors.ghidra.helpers.is_sp_modified(insn):
        # skip things like:
        #   .text:00401145 add esp, 0Ch
        return

    for i in range(insn.getNumOperands()):
        # Exceptions for LEA insn:
        # invalid operand encoding, considered numbers instead of offsets
        # see: mimikatz.exe_:0x4018C0
        if insn.getOperandType(i) == OperandType.DYNAMIC and insn.getMnemonicString().startswith("LEA"):
            # Additional check, avoid yielding "wide" values (ex. mimikatz.exe:0x471EE6 LEA EBX, [ECX + EAX*0x4])
            op_objs = insn.getOpObjects(i)
            if len(op_objs) == 3:  # ECX, EAX, 0x4
                continue

            if isinstance(op_objs[-1], ghidra.program.model.scalar.Scalar):
                const = op_objs[-1].getUnsignedValue()
                addr = ih.address

                yield Number(const), addr
                yield OperandNumber(i, const), addr
        elif not OperandType.isScalar(insn.getOperandType(i)):
            # skip things like:
            #   references, void types
            continue
        else:
            const = insn.getScalar(i).getUnsignedValue()
            addr = ih.address

            yield Number(const), addr
            yield OperandNumber(i, const), addr

            if insn.getMnemonicString().startswith("ADD") and 0 < const < MAX_STRUCTURE_SIZE:
                # for pattern like:
                #
                #     add eax, 0x10
                #
                # assume 0x10 is also an offset (imagine eax is a pointer).
                yield Offset(const), addr
                yield OperandOffset(i, const), addr


def extract_insn_offset_features(fh: FunctionHandle, bb: BBHandle, ih: InsnHandle) -> Iterator[tuple[Feature, Address]]:
    """
    parse instruction structure offset features

    example:
        .text:0040112F cmp [esi+4], ebx
    """
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    if insn.getMnemonicString().startswith("LEA"):
        return

    if capa.features.extractors.ghidra.helpers.is_stack_referenced(insn):
        # ignore stack references
        return

    # Ghidra stores operands in 2D arrays if they contain offsets
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == OperandType.DYNAMIC:  # e.g. [esi + 4]
            # manual extraction, since the default api calls only work on the 1st dimension of the array
            op_objs = insn.getOpObjects(i)
            if not op_objs:
                continue

            if isinstance(op_objs[-1], ghidra.program.model.scalar.Scalar):
                op_off = op_objs[-1].getValue()
            else:
                op_off = 0

            yield Offset(op_off), ih.address
            yield OperandOffset(i, op_off), ih.address


def extract_insn_bytes_features(fh: FunctionHandle, bb: BBHandle, ih: InsnHandle) -> Iterator[tuple[Feature, Address]]:
    """
    parse referenced byte sequences

    example:
        push    offset iid_004118d4_IShellLinkA ; riid
    """
    for addr in capa.features.extractors.ghidra.helpers.find_data_references_from_insn(ih.inner):
        data = getDataAt(addr)  # type: ignore [name-defined] # noqa: F821
        if data and not data.hasStringValue():
            extracted_bytes = capa.features.extractors.ghidra.helpers.get_bytes(addr, MAX_BYTES_FEATURE_SIZE)
            if extracted_bytes and not capa.features.extractors.helpers.all_zeros(extracted_bytes):
                yield Bytes(extracted_bytes), ih.address


def extract_insn_string_features(fh: FunctionHandle, bb: BBHandle, ih: InsnHandle) -> Iterator[tuple[Feature, Address]]:
    """
    parse instruction string features

    example:
        push offset aAcr     ; "ACR  > "
    """
    for addr in capa.features.extractors.ghidra.helpers.find_data_references_from_insn(ih.inner):
        data = getDataAt(addr)  # type: ignore [name-defined] # noqa: F821
        if data and data.hasStringValue():
            yield String(data.getValue()), ih.address


def extract_insn_mnemonic_features(
    fh: FunctionHandle, bb: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """parse instruction mnemonic features"""
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    yield Mnemonic(insn.getMnemonicString().lower()), ih.address


def extract_insn_obfs_call_plus_5_characteristic_features(
    fh: FunctionHandle, bb: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """
    parse call $+5 instruction from the given instruction.
    """
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    if not capa.features.extractors.ghidra.helpers.is_call_or_jmp(insn):
        return

    code_ref = OperandType.ADDRESS | OperandType.CODE
    ref = insn.getAddress()
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == code_ref:
            ref = insn.getAddress(i)

    if insn.getAddress().add(5) == ref:
        yield Characteristic("call $+5"), ih.address


def extract_insn_segment_access_features(
    fh: FunctionHandle, bb: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """parse instruction fs or gs access"""
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    insn_str = insn.toString()

    if "FS:" in insn_str:
        yield Characteristic("fs access"), ih.address

    if "GS:" in insn_str:
        yield Characteristic("gs access"), ih.address


def extract_insn_peb_access_characteristic_features(
    fh: FunctionHandle, bb: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """parse instruction peb access

    fs:[0x30] on x86, gs:[0x60] on x64

    """
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    insn_str = insn.toString()
    if insn_str.startswith(("PUSH", "MOV")):
        if "FS:[0x30]" in insn_str or "GS:[0x60]" in insn_str:
            yield Characteristic("peb access"), ih.address


def extract_insn_cross_section_cflow(
    fh: FunctionHandle, bb: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """inspect the instruction for a CALL or JMP that crosses section boundaries"""
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    if not capa.features.extractors.ghidra.helpers.is_call_or_jmp(insn):
        return

    externs = get_externs(fh.ctx)
    fakes = get_fakes(fh.ctx)
    imports = get_imports(fh.ctx)

    # OperandType to dereference
    addr_data = OperandType.ADDRESS | OperandType.DATA
    addr_code = OperandType.ADDRESS | OperandType.CODE

    ref_type = insn.getOperandType(0)

    # both OperandType flags must be present
    # bail on REGISTER alone
    if OperandType.isRegister(ref_type):
        if OperandType.isAddress(ref_type):
            ref = insn.getAddress(0)  # Ghidra dereferences REG | ADDR
            if capa.features.extractors.ghidra.helpers.check_addr_for_api(ref, fakes, imports, externs):
                return
        else:
            return
    elif ref_type in (addr_data, addr_code) or (OperandType.isIndirect(ref_type) and OperandType.isAddress(ref_type)):
        # we must dereference and check if the addr is a pointer to an api function
        ref = capa.features.extractors.ghidra.helpers.dereference_ptr(insn)
        if capa.features.extractors.ghidra.helpers.check_addr_for_api(ref, fakes, imports, externs):
            return
    elif ref_type == OPERAND_TYPE_DYNAMIC_ADDRESS or ref_type == OperandType.DYNAMIC:
        return  # cannot resolve dynamics statically
    else:
        # pure address does not need to get dereferenced/ handled
        ref = insn.getAddress(0)
        if not ref:
            # If it returned null, it was an indirect
            # that had no address reference.
            # This check is faster than checking for (indirect and not address)
            return
        if capa.features.extractors.ghidra.helpers.check_addr_for_api(ref, fakes, imports, externs):
            return

    this_mem_block = getMemoryBlock(insn.getAddress())  # type: ignore [name-defined] # noqa: F821
    ref_block = getMemoryBlock(ref)  # type: ignore [name-defined] # noqa: F821
    if ref_block != this_mem_block:
        yield Characteristic("cross section flow"), ih.address


def extract_function_calls_from(
    fh: FunctionHandle,
    bb: BBHandle,
    ih: InsnHandle,
) -> Iterator[tuple[Feature, Address]]:
    """extract functions calls from features

    most relevant at the function scope, however, its most efficient to extract at the instruction scope
    """
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    if insn.getMnemonicString().startswith("CALL"):
        # This method of "dereferencing" addresses/ pointers
        # is not as robust as methods in other functions,
        # but works just fine for this one
        reference = 0
        for ref in insn.getReferencesFrom():
            addr = ref.getToAddress()

            # avoid returning fake addrs
            if not addr.isExternalAddress():
                reference = addr.getOffset()

            # if a reference is < 0, then ghidra pulled an offset from a DYNAMIC | ADDR (usually a stackvar)
            # these cannot be resolved to actual addrs
            if reference > 0:
                yield Characteristic("calls from"), AbsoluteVirtualAddress(reference)


def extract_function_indirect_call_characteristic_features(
    fh: FunctionHandle,
    bb: BBHandle,
    ih: InsnHandle,
) -> Iterator[tuple[Feature, Address]]:
    """extract indirect function calls (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974

    most relevant at the function or basic block scope;
    however, its most efficient to extract at the instruction scope
    """
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    if insn.getMnemonicString().startswith("CALL"):
        if OperandType.isRegister(insn.getOperandType(0)):
            yield Characteristic("indirect call"), ih.address
        if OperandType.isIndirect(insn.getOperandType(0)):
            yield Characteristic("indirect call"), ih.address


def check_nzxor_security_cookie_delta(
    fh: ghidra.program.database.function.FunctionDB, insn: ghidra.program.database.code.InstructionDB
):
    """Get the function containing the insn
    Get the last block of the function that contains the insn

    Check the bb containing the insn
    Check the last bb of the function containing the insn
    """

    model = SimpleBlockModel(currentProgram())  # type: ignore [name-defined] # noqa: F821
    insn_addr = insn.getAddress()
    func_asv = fh.getBody()
    first_addr = func_asv.getMinAddress()
    last_addr = func_asv.getMaxAddress()

    if model.getFirstCodeBlockContaining(
        first_addr, monitor()  # type: ignore [name-defined] # noqa: F821
    ) == model.getFirstCodeBlockContaining(
        last_addr, monitor()  # type: ignore [name-defined] # noqa: F821
    ):
        if insn_addr < first_addr.add(SECURITY_COOKIE_BYTES_DELTA):
            return True
        else:
            return insn_addr > last_addr.add(SECURITY_COOKIE_BYTES_DELTA * -1)
    else:
        return False


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle,
    bb: BBHandle,
    ih: InsnHandle,
) -> Iterator[tuple[Feature, Address]]:
    f: ghidra.program.database.function.FunctionDB = fh.inner
    insn: ghidra.program.database.code.InstructionDB = ih.inner

    if "XOR" not in insn.getMnemonicString():
        return
    if capa.features.extractors.ghidra.helpers.is_stack_referenced(insn):
        return
    if capa.features.extractors.ghidra.helpers.is_zxor(insn):
        return
    if check_nzxor_security_cookie_delta(f, insn):
        return
    yield Characteristic("nzxor"), ih.address


def extract_features(
    fh: FunctionHandle,
    bb: BBHandle,
    insn: InsnHandle,
) -> Iterator[tuple[Feature, Address]]:
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature, addr in insn_handler(fh, bb, insn):
            yield feature, addr


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_bytes_features,
    extract_insn_string_features,
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


def main():
    """ """
    features = []
    from capa.features.extractors.ghidra.extractor import GhidraFeatureExtractor

    for fh in GhidraFeatureExtractor().get_functions():
        for bb in capa.features.extractors.ghidra.helpers.get_function_blocks(fh):
            for insn in capa.features.extractors.ghidra.helpers.get_insn_in_range(bb):
                features.extend(list(extract_features(fh, bb, insn)))

    import pprint

    pprint.pprint(features)  # noqa: T203


if __name__ == "__main__":
    main()
