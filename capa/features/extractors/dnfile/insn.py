# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Tuple, Iterator, Optional

if TYPE_CHECKING:
    from dncil.cil.instruction import Instruction
    from dncil.cil.body import CilMethodBody
    from capa.features.common import Feature

import dnfile
from dncil.clr.token import StringToken, InvalidToken
from dncil.cil.opcode import OpCodes

import capa.features.extractors.helpers
from capa.features.insn import API, Number
from capa.features.common import String, Characteristic
from capa.features.extractors.dnfile.helpers import (
    resolve_dotnet_token,
    read_dotnet_user_string,
    get_dotnet_managed_imports,
    get_dotnet_unmanaged_imports,
    get_dotnet_managed_method_names,
)


def get_managed_imports(ctx: Dict) -> Dict:
    if "managed_imports_cache" not in ctx:
        ctx["managed_imports_cache"] = {}
        for (token, name) in get_dotnet_managed_imports(ctx["pe"]):
            ctx["managed_imports_cache"][token] = name
    return ctx["managed_imports_cache"]


def get_unmanaged_imports(ctx: Dict) -> Dict:
    if "unmanaged_imports_cache" not in ctx:
        ctx["unmanaged_imports_cache"] = {}
        for (token, name) in get_dotnet_unmanaged_imports(ctx["pe"]):
            ctx["unmanaged_imports_cache"][token] = name
    return ctx["unmanaged_imports_cache"]


def get_methods(ctx: Dict) -> Dict:
    if "methods_cache" not in ctx:
        ctx["methods_cache"] = {}
        for (token, name) in get_dotnet_managed_method_names(ctx["pe"]):
            ctx["methods_cache"][token] = name
    return ctx["methods_cache"]


def get_callee_name(ctx: Dict, token: int) -> str:
    """map dotnet token to method name"""
    name: str = get_managed_imports(ctx).get(token, "")
    if not name:
        # we must check unmanaged imports before managed methods because we map forwarded managed methods
        # to their unmanaged imports; we prefer a forwarded managed method be mapped to its unmanaged import for analysis
        name = get_unmanaged_imports(ctx).get(token, "")
        if not name:
            name = get_methods(ctx).get(token, "")
    return name


def extract_insn_api_features(f: CilMethodBody, bb: CilMethodBody, insn: Instruction) -> Iterator[Tuple[API, int]]:
    """parse instruction API features"""
    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    name: str = get_callee_name(f.ctx, insn.operand.value)
    if not name:
        return

    if "::" in name:
        # like System.IO.File::OpenRead
        yield API(name), insn.offset
    else:
        # like kernel32.CreateFileA
        dll, _, symbol = name.rpartition(".")
        for name_variant in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield API(name_variant), insn.offset


def extract_insn_number_features(
    f: CilMethodBody, bb: CilMethodBody, insn: Instruction
) -> Iterator[Tuple[Number, int]]:
    """parse instruction number features"""
    if insn.is_ldc():
        yield Number(insn.get_ldc()), insn.offset


def extract_insn_string_features(
    f: CilMethodBody, bb: CilMethodBody, insn: Instruction
) -> Iterator[Tuple[String, int]]:
    """parse instruction string features"""
    if not insn.is_ldstr():
        return

    if not isinstance(insn.operand, StringToken):
        return

    user_string: Optional[str] = read_dotnet_user_string(f.ctx["pe"], insn.operand)
    if user_string is None:
        return

    yield String(user_string), insn.offset


def extract_unmanaged_call_characteristic_features(
    f: CilMethodBody, bb: CilMethodBody, insn: Instruction
) -> Iterator[Tuple[Characteristic, int]]:
    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    token: Any = resolve_dotnet_token(f.ctx["pe"], insn.operand)
    if isinstance(token, InvalidToken):
        return
    if not isinstance(token, dnfile.mdtable.MethodDefRow):
        return

    if any((token.Flags.mdPinvokeImpl, token.ImplFlags.miUnmanaged, token.ImplFlags.miNative)):
        yield Characteristic("unmanaged call"), insn.offset


def extract_features(f: CilMethodBody, bb: CilMethodBody, insn: Instruction) -> Iterator[Tuple[Feature, int]]:
    """extract instruction features"""
    for inst_handler in INSTRUCTION_HANDLERS:
        for (feature, offset) in inst_handler(f, bb, insn):
            yield feature, offset


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_string_features,
    extract_unmanaged_call_characteristic_features,
)
