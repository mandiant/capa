# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import Any, Dict, Tuple, Union, Iterator, Optional

import dnfile
from dncil.cil.body import CilMethodBody
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.opcode import OpCodes
from dncil.cil.instruction import Instruction

import capa.features.extractors.helpers
from capa.features.insn import API, Number, Property
from capa.features.common import Class, String, Feature, Namespace, Characteristic
from capa.features.address import Address
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.dnfile.helpers import (
    DnClass,
    DnMethod,
    DnProperty,
    DnUnmanagedMethod,
    get_dotnet_fields,
    resolve_dotnet_token,
    get_dotnet_properties,
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


def get_properties(ctx: Dict) -> Dict:
    if "properties_cache" not in ctx:
        ctx["properties_cache"] = {}
        for property in get_dotnet_properties(ctx["pe"]):
            if property is not None:
                ctx["properties_cache"][property.token] = property
    return ctx["properties_cache"]


def get_fields(ctx: Dict) -> Dict:
    if "fields_cache" not in ctx:
        ctx["fields_cache"] = {}
        for field in get_dotnet_fields(ctx["pe"]):
            ctx["fields_cache"][field.token] = field
    return ctx["fields_cache"]


def extract_insn_api_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction API features"""
    insn: Instruction = ih.inner

    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    callee: Union[DnMethod, DnUnmanagedMethod, None] = get_callee(fh.ctx, insn.operand.value)
    if callee is None:
        return

    if callee.methodname.startswith(("get_", "set_")):
        if Token(insn.operand.value).table == 6:
            """check if the method belongs to the MethodDef table and whether it is used to access a property"""
            row: Optional[DnProperty] = get_properties(fh.ctx).get(insn.operand.value, None)
            if row is not None:
                return
        elif Token(insn.operand.value).table == 10:
            """if the method belongs to the MemberRef table, we assume it is used to access a property"""
            return

    if isinstance(callee, DnUnmanagedMethod):
        # like kernel32.CreateFileA
        for name in capa.features.extractors.helpers.generate_symbols(callee.modulename, callee.methodname):
            yield API(name), ih.address
    else:
        # like System.IO.File::Delete
        yield API(str(callee)), ih.address


def extract_insn_property_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction property features"""
    insn: Instruction = ih.inner

    if insn.opcode in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        token: Token = Token(insn.operand.value)
        if token.table == 6:
            """check if the method belongs to the MethodDef table and whether it is used to access a property"""
            property: Optional[DnProperty] = get_properties(fh.ctx).get(insn.operand.value, None)
            if property is None:
                return
            yield Property(str(property)), ih.address

        elif token.table == 10:
            """if the method belongs to the MemberRef table, we assume it is used to access a property"""
            row: Any = resolve_dotnet_token(fh.ctx["pe"], token)
            if row is None:
                return
            if row.Name.startswith(("get_", "set_")):
                name = row.Name[4:]
            else:
                return
            if not isinstance(row.Class.row, (dnfile.mdtable.TypeRefRow, dnfile.mdtable.TypeDefRow)):
                return
            yield Property(
                DnProperty.format_name(row.Class.row.TypeNamespace, row.Class.row.TypeName, name)
            ), ih.address

    if insn.opcode in (OpCodes.Ldfld, OpCodes.Ldflda, OpCodes.Ldsfld, OpCodes.Ldsflda, OpCodes.Stfld, OpCodes.Stsfld):
        field_token: Token = Token(insn.operand.value)
        if field_token.table == 4:
            """determine whether the operand is a field by checking if it belongs to the Field table"""
            field: Optional[DnProperty] = get_fields(fh.ctx).get(insn.operand.value, None)
            if field is None:
                return
            yield Property(str(field)), ih.address

    return


def extract_insn_class_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Class, Address]]:
    """parse instruction class features"""
    if ih.inner.opcode not in (
        OpCodes.Call,
        OpCodes.Callvirt,
        OpCodes.Jmp,
        OpCodes.Calli,
        OpCodes.Ldfld,
        OpCodes.Ldflda,
        OpCodes.Ldsfld,
        OpCodes.Ldsflda,
        OpCodes.Stfld,
        OpCodes.Stsfld,
    ):
        return

    row: Any = resolve_dotnet_token(fh.ctx["pe"], Token(ih.inner.operand.value))
    if isinstance(row, dnfile.mdtable.MemberRefRow):
        if isinstance(row.Class.row, (dnfile.mdtable.TypeRefRow, dnfile.mdtable.TypeDefRow)):
            yield Class(DnClass.format_name(row.Class.row.TypeNamespace, row.Class.row.TypeName)), ih.address

    elif isinstance(row, dnfile.mdtable.MethodDefRow):
        callee: Union[DnMethod, DnUnmanagedMethod, None] = get_callee(fh.ctx, ih.inner.operand.value)
        if isinstance(callee, DnMethod):
            yield Class(DnClass.format_name(callee.namespace, callee.classname)), ih.address
        else:
            return

    elif isinstance(row, dnfile.mdtable.FieldRow):
        field: Optional[DnProperty] = get_fields(fh.ctx).get(ih.inner.operand.value, None)
        if field is None:
            return
        yield Class(DnClass.format_name(field.namespace, field.classname)), ih.address


def extract_insn_namespace_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Namespace, Address]]:
    """parse instruction namespace features"""
    if ih.inner.opcode not in (
        OpCodes.Call,
        OpCodes.Callvirt,
        OpCodes.Jmp,
        OpCodes.Calli,
        OpCodes.Ldfld,
        OpCodes.Ldflda,
        OpCodes.Ldsfld,
        OpCodes.Ldsflda,
        OpCodes.Stfld,
        OpCodes.Stsfld,
    ):
        return

    row: Any = resolve_dotnet_token(fh.ctx["pe"], Token(ih.inner.operand.value))

    if isinstance(row, dnfile.mdtable.MemberRefRow):
        if isinstance(row.Class.row, (dnfile.mdtable.TypeRefRow, dnfile.mdtable.TypeDefRow)):
            if row.Class.row.TypeNamespace:
                yield Namespace(row.Class.row.TypeNamespace), ih.address

    elif isinstance(row, dnfile.mdtable.MethodDefRow):
        callee: Union[DnMethod, DnUnmanagedMethod, None] = get_callee(fh.ctx, ih.inner.operand.value)
        if isinstance(callee, DnMethod):
            if callee.namespace is None:
                return
            yield Namespace(callee.namespace), ih.address

    elif isinstance(row, dnfile.mdtable.FieldRow):
        field: Optional[DnProperty] = get_fields(fh.ctx).get(ih.inner.operand.value, None)
        if field is None:
            return
        yield Namespace(field.namespace), ih.address


def extract_insn_number_features(fh, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction number features"""
    insn: Instruction = ih.inner

    if insn.is_ldc():
        yield Number(insn.get_ldc()), ih.address


def extract_insn_string_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction string features"""
    f: CilMethodBody = fh.inner
    insn: Instruction = ih.inner

    if not insn.is_ldstr():
        return

    if not isinstance(insn.operand, StringToken):
        return

    user_string: Optional[str] = read_dotnet_user_string(fh.ctx["pe"], insn.operand)
    if user_string is None:
        return

    yield String(user_string), ih.address


def extract_unmanaged_call_characteristic_features(
    fh: FunctionHandle, bb: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Characteristic, Address]]:
    insn: Instruction = ih.inner
    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    token: Any = resolve_dotnet_token(fh.ctx["pe"], insn.operand)
    if isinstance(token, InvalidToken):
        return
    if not isinstance(token, dnfile.mdtable.MethodDefRow):
        return

    if any((token.Flags.mdPinvokeImpl, token.ImplFlags.miUnmanaged, token.ImplFlags.miNative)):
        yield Characteristic("unmanaged call"), ih.address


def extract_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract instruction features"""
    for inst_handler in INSTRUCTION_HANDLERS:
        for (feature, addr) in inst_handler(fh, bbh, ih):
            assert isinstance(addr, Address)
            yield feature, addr


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_property_features,
    extract_insn_number_features,
    extract_insn_string_features,
    extract_insn_namespace_features,
    extract_insn_class_features,
    extract_unmanaged_call_characteristic_features,
)
