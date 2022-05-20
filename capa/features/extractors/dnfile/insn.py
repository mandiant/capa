# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Tuple, Union, Iterator, Optional

if TYPE_CHECKING:
    from dncil.cil.instruction import Instruction
    from dncil.cil.body import CilMethodBody
    from capa.features.common import Feature

import dnfile
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.opcode import OpCodes

import capa.features.extractors.helpers
from capa.features.insn import API, Number
from capa.features.common import Class, String, Namespace, Characteristic
from capa.features.extractors.dnfile.helpers import (
    DnClass,
    DnMethod,
    DnUnmanagedMethod,
    resolve_dotnet_token,
    read_dotnet_user_string,
    get_dotnet_managed_imports,
    get_dotnet_managed_methods,
    get_dotnet_unmanaged_imports,
)


def get_managed_imports(ctx: Dict) -> Dict:
    if "managed_imports_cache" not in ctx:
        ctx["managed_imports_cache"] = {}
        for method in get_dotnet_managed_imports(ctx["pe"]):
            ctx["managed_imports_cache"][method.token] = method
    return ctx["managed_imports_cache"]


def get_unmanaged_imports(ctx: Dict) -> Dict:
    if "unmanaged_imports_cache" not in ctx:
        ctx["unmanaged_imports_cache"] = {}
        for imp in get_dotnet_unmanaged_imports(ctx["pe"]):
            ctx["unmanaged_imports_cache"][imp.token] = imp
    return ctx["unmanaged_imports_cache"]


def get_methods(ctx: Dict) -> Dict:
    if "methods_cache" not in ctx:
        ctx["methods_cache"] = {}
        for method in get_dotnet_managed_methods(ctx["pe"]):
            ctx["methods_cache"][method.token] = method
    return ctx["methods_cache"]


def get_callee(ctx: Dict, token: int) -> Union[DnMethod, DnUnmanagedMethod, None]:
    """map dotnet token to un/managed method"""
    callee: Union[DnMethod, DnUnmanagedMethod, None] = get_managed_imports(ctx).get(token, None)
    if not callee:
        # we must check unmanaged imports before managed methods because we map forwarded managed methods
        # to their unmanaged imports; we prefer a forwarded managed method be mapped to its unmanaged import for analysis
        callee = get_unmanaged_imports(ctx).get(token, None)
        if not callee:
            callee = get_methods(ctx).get(token, None)
    return callee


def extract_insn_api_features(f: CilMethodBody, bb: CilMethodBody, insn: Instruction) -> Iterator[Tuple[API, int]]:
    """parse instruction API features"""
    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    callee: Union[DnMethod, DnUnmanagedMethod, None] = get_callee(f.ctx, insn.operand.value)
    if callee is None:
        return

    if isinstance(callee, DnUnmanagedMethod):
        # like kernel32.CreateFileA
        for name in capa.features.extractors.helpers.generate_symbols(callee.modulename, callee.methodname):
            yield API(name), insn.offset
    else:
        # like System.IO.File::Delete
        yield API(str(callee)), insn.offset


def extract_insn_class_features(f: CilMethodBody, bb: CilMethodBody, insn: Instruction) -> Iterator[Tuple[Class, int]]:
    """parse instruction class features"""
    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    row: Any = resolve_dotnet_token(f.ctx["pe"], Token(insn.operand.value))

    if not isinstance(row, dnfile.mdtable.MemberRefRow):
        return
    if not isinstance(row.Class.row, (dnfile.mdtable.TypeRefRow, dnfile.mdtable.TypeDefRow)):
        return

    yield Class(DnClass.format_name(row.Class.row.TypeNamespace, row.Class.row.TypeName)), insn.offset


def extract_insn_namespace_features(
    f: CilMethodBody, bb: CilMethodBody, insn: Instruction
) -> Iterator[Tuple[Namespace, int]]:
    """parse instruction namespace features"""
    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    row: Any = resolve_dotnet_token(f.ctx["pe"], Token(insn.operand.value))

    if not isinstance(row, dnfile.mdtable.MemberRefRow):
        return
    if not isinstance(row.Class.row, (dnfile.mdtable.TypeRefRow, dnfile.mdtable.TypeDefRow)):
        return
    if not row.Class.row.TypeNamespace:
        return

    yield Namespace(row.Class.row.TypeNamespace), insn.offset


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
    extract_insn_namespace_features,
    extract_insn_class_features,
    extract_unmanaged_call_characteristic_features,
)
