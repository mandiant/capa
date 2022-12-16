# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import logging
from typing import Dict, Tuple, Union, Iterator, Optional

import dnfile
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.opcode import OpCodes
from dncil.cil.instruction import Instruction

import capa.features.extractors.helpers
from capa.features.insn import API, Number, Property
from capa.features.common import Class, String, Feature, Namespace, FeatureAccess, Characteristic
from capa.features.address import Address
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.dnfile.helpers import (
    DnType,
    DnUnmanagedMethod,
    get_dotnet_fields,
    resolve_dotnet_token,
    get_dotnet_properties,
    read_dotnet_user_string,
    resolve_dotnet_methodspec,
    get_dotnet_managed_imports,
    get_dotnet_managed_methods,
    get_dotnet_unmanaged_imports,
)

logger = logging.getLogger(__name__)


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


def get_callee(ctx: Dict, token: Token) -> Union[DnType, DnUnmanagedMethod, None]:
    """map dotnet token to un/managed method"""
    row: Union[dnfile.base.MDTableRow, str, None] = resolve_dotnet_token(ctx["pe"], token)
    if not isinstance(row, (dnfile.mdtable.MethodDefRow, dnfile.mdtable.MemberRefRow, dnfile.mdtable.GenericMethodRow)):
        return None

    token_: Optional[int]
    if isinstance(row, dnfile.mdtable.GenericMethodRow):
        # map MethodSpec to MethodDef or MemberRef
        token_ = resolve_dotnet_methodspec(ctx["pe"], token)
    else:
        token_ = token.value

    if token_ is None:
        return None

    callee: Union[DnType, DnUnmanagedMethod, None] = get_managed_imports(ctx).get(token_, None)
    if callee is None:
        # we must check unmanaged imports before managed methods because we map forwarded managed methods
        # to their unmanaged imports; we prefer a forwarded managed method be mapped to its unmanaged import for analysis
        callee = get_unmanaged_imports(ctx).get(token_, None)
        if callee is None:
            callee = get_methods(ctx).get(token_, None)
    return callee


def get_properties(ctx: Dict) -> Dict:
    if "properties_cache" not in ctx:
        ctx["properties_cache"] = {}
        for prop in get_dotnet_properties(ctx["pe"]):
            ctx["properties_cache"][prop.token] = prop
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

    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli, OpCodes.Newobj):
        return

    callee: Union[DnType, DnUnmanagedMethod, None] = get_callee(fh.ctx, insn.operand)
    if callee is None:
        return

    if isinstance(callee, DnType):
        if callee.member.startswith(("get_", "set_")):
            if insn.operand.table == dnfile.mdtable.MethodDef.number:
                # check if the method belongs to the MethodDef table and whether it is used to access a property
                if get_properties(fh.ctx).get(insn.operand.value, None) is not None:
                    return
            elif insn.operand.table == dnfile.mdtable.MemberRef.number:
                # if the method belongs to the MemberRef table, we assume it is used to access a property
                return

        # like System.IO.File::Delete
        yield API(str(callee)), ih.address

    else:
        # like kernel32.CreateFileA
        for name in capa.features.extractors.helpers.generate_symbols(callee.module, callee.method):
            yield API(name), ih.address


def extract_insn_property_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction property features"""
    insn: Instruction = ih.inner

    name: Optional[str] = None
    access: Optional[str] = None

    if insn.opcode in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        if insn.operand.table == dnfile.mdtable.MethodDef.number:
            # check if the method belongs to the MethodDef table and whether it is used to access a property
            prop: Optional[DnType] = get_properties(fh.ctx).get(insn.operand.value, None)
            if prop is not None:
                name = str(prop)
                access = prop.access

        elif insn.operand.table == dnfile.mdtable.MemberRef.number:
            # if the method belongs to the MemberRef table, we assume it is used to access a property
            row: Union[str, InvalidToken, dnfile.base.MDTableRow] = resolve_dotnet_token(fh.ctx["pe"], insn.operand)

            if not isinstance(row, dnfile.mdtable.MemberRefRow):
                return
            if not isinstance(row.Class.row, (dnfile.mdtable.TypeRefRow, dnfile.mdtable.TypeDefRow)):
                return
            if not row.Name.startswith(("get_", "set_")):
                return

            name = DnType.format_name(
                row.Class.row.TypeName, namespace=row.Class.row.TypeNamespace, member=row.Name[4:]
            )

            if row.Name.startswith("get_"):
                access = FeatureAccess.READ
            elif row.Name.startswith("set_"):
                access = FeatureAccess.WRITE

    elif insn.opcode in (OpCodes.Ldfld, OpCodes.Ldflda, OpCodes.Ldsfld, OpCodes.Ldsflda):
        if insn.operand.table == dnfile.mdtable.Field.number:
            # determine whether the operand is a field by checking if it belongs to the Field table
            read_field: Optional[DnType] = get_fields(fh.ctx).get(insn.operand.value, None)
            if read_field is not None:
                name = str(read_field)
                access = FeatureAccess.READ

    elif insn.opcode in (OpCodes.Stfld, OpCodes.Stsfld):
        if insn.operand.table == dnfile.mdtable.Field.number:
            # determine whether the operand is a field by checking if it belongs to the Field table
            write_field: Optional[DnType] = get_fields(fh.ctx).get(insn.operand.value, None)
            if write_field is not None:
                name = str(write_field)
                access = FeatureAccess.WRITE

    if name is not None:
        if access is not None:
            yield Property(name, access=access), ih.address
        yield Property(name), ih.address


def extract_insn_class_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Class, Address]]:
    """parse instruction class features"""
    if ih.inner.opcode in (
        OpCodes.Call,
        OpCodes.Callvirt,
        OpCodes.Jmp,
        OpCodes.Calli,
        OpCodes.Newobj,
    ):
        callee: Union[DnType, DnUnmanagedMethod, None] = get_callee(fh.ctx, ih.inner.operand)
        if isinstance(callee, DnType):
            yield Class(DnType.format_name(callee.class_, namespace=callee.namespace)), ih.address

    elif ih.inner.opcode in (
        OpCodes.Ldfld,
        OpCodes.Ldflda,
        OpCodes.Ldsfld,
        OpCodes.Ldsflda,
        OpCodes.Stfld,
        OpCodes.Stsfld,
    ):
        row: Union[str, InvalidToken, dnfile.base.MDTableRow] = resolve_dotnet_token(fh.ctx["pe"], ih.inner.operand)
        if not isinstance(row, dnfile.mdtable.FieldRow):
            return

        field: Optional[DnType] = get_fields(fh.ctx).get(ih.inner.operand.value, None)
        if field is not None:
            yield Class(DnType.format_name(field.class_, namespace=field.namespace)), ih.address


def extract_insn_namespace_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Namespace, Address]]:
    """parse instruction namespace features"""
    """parse instruction class features"""
    if ih.inner.opcode in (
        OpCodes.Call,
        OpCodes.Callvirt,
        OpCodes.Jmp,
        OpCodes.Calli,
        OpCodes.Newobj,
    ):
        callee: Union[DnType, DnUnmanagedMethod, None] = get_callee(fh.ctx, ih.inner.operand)
        if isinstance(callee, DnType) and callee.namespace is not None:
            yield Namespace(callee.namespace), ih.address

    elif ih.inner.opcode in (
        OpCodes.Ldfld,
        OpCodes.Ldflda,
        OpCodes.Ldsfld,
        OpCodes.Ldsflda,
        OpCodes.Stfld,
        OpCodes.Stsfld,
    ):
        row: Union[str, InvalidToken, dnfile.base.MDTableRow] = resolve_dotnet_token(fh.ctx["pe"], ih.inner.operand)
        if not isinstance(row, dnfile.mdtable.FieldRow):
            return

        field: Optional[DnType] = get_fields(fh.ctx).get(ih.inner.operand.value, None)
        if isinstance(field, DnType) and field.namespace is not None:
            yield Namespace(field.namespace), ih.address


def extract_insn_number_features(fh, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction number features"""
    insn: Instruction = ih.inner

    if insn.is_ldc():
        yield Number(insn.get_ldc()), ih.address


def extract_insn_string_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction string features"""
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

    row: Union[str, InvalidToken, dnfile.base.MDTableRow] = resolve_dotnet_token(fh.ctx["pe"], insn.operand)
    if not isinstance(row, dnfile.mdtable.MethodDefRow):
        return

    if any((row.Flags.mdPinvokeImpl, row.ImplFlags.miUnmanaged, row.ImplFlags.miNative)):
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
