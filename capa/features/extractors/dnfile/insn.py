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
    read_dotnet_user_string,
    get_dotnet_managed_imports,
    get_dotnet_managed_methods,
    calculate_dotnet_token_value,
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


def get_fields(ctx: Dict) -> Dict:
    if "fields_cache" not in ctx:
        ctx["fields_cache"] = {}
        for field in get_dotnet_fields(ctx["pe"]):
            ctx["fields_cache"][field.token] = field
    return ctx["fields_cache"]


def get_callee(ctx: Dict, token: Token) -> Union[DnType, DnUnmanagedMethod, None]:
    """map .NET token to un/managed (generic) method"""
    row: Union[dnfile.base.MDTableRow, InvalidToken, str] = resolve_dotnet_token(ctx["pe"], token)
    if not isinstance(row, (dnfile.mdtable.MethodDefRow, dnfile.mdtable.MemberRefRow, dnfile.mdtable.MethodSpecRow)):
        # we only handle MethodDef (internal), MemberRef (external), and MethodSpec (generic)
        return None

    token_: int
    if isinstance(row, dnfile.mdtable.MethodSpecRow):
        # map MethodSpec to MethodDef or MemberRef
        if row.Method.table is None:
            logger.debug("MethodSpec[0x%X] Method table is None", token.rid)
            return None
        token_ = calculate_dotnet_token_value(row.Method.table.number, row.Method.row_index)
    else:
        token_ = token.value

    callee: Union[DnType, DnUnmanagedMethod, None] = get_managed_imports(ctx).get(token_, None)
    if callee is None:
        # we must check unmanaged imports before managed methods because we map forwarded managed methods
        # to their unmanaged imports; we prefer a forwarded managed method be mapped to its unmanaged import for analysis
        callee = get_unmanaged_imports(ctx).get(token_, None)
        if callee is None:
            callee = get_methods(ctx).get(token_, None)
    return callee


def extract_insn_api_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction API features"""
    if ih.inner.opcode not in (
        OpCodes.Call,
        OpCodes.Callvirt,
        OpCodes.Jmp,
        OpCodes.Newobj,
    ):
        return

    callee: Union[DnType, DnUnmanagedMethod, None] = get_callee(fh.ctx, ih.inner.operand)
    if isinstance(callee, DnType):
        # ignore methods used to access properties
        if callee.access is None:
            # like System.IO.File::Delete
            yield API(str(callee)), ih.address
    elif isinstance(callee, DnUnmanagedMethod):
        # like kernel32.CreateFileA
        for name in capa.features.extractors.helpers.generate_symbols(callee.module, callee.method):
            yield API(name), ih.address


def extract_insn_property_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction property features"""
    name: Optional[str] = None
    access: Optional[str] = None

    if ih.inner.opcode in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp):
        # property access via MethodDef or MemberRef
        callee: Union[DnType, DnUnmanagedMethod, None] = get_callee(fh.ctx, ih.inner.operand)
        if isinstance(callee, DnType):
            if callee.access is not None:
                name = str(callee)
                access = callee.access

    elif ih.inner.opcode in (OpCodes.Ldfld, OpCodes.Ldflda, OpCodes.Ldsfld, OpCodes.Ldsflda):
        # property read via Field
        read_field: Optional[DnType] = get_fields(fh.ctx).get(ih.inner.operand.value, None)
        if read_field is not None:
            name = str(read_field)
            access = FeatureAccess.READ

    elif ih.inner.opcode in (OpCodes.Stfld, OpCodes.Stsfld):
        # property write via Field
        write_field: Optional[DnType] = get_fields(fh.ctx).get(ih.inner.operand.value, None)
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
        OpCodes.Ldvirtftn,
        OpCodes.Ldftn,
        OpCodes.Newobj,
    ):
        # method call - includes managed methods (MethodDef, TypeRef) and properties (MethodSemantics, TypeRef)
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
        # field access
        field: Optional[DnType] = get_fields(fh.ctx).get(ih.inner.operand.value, None)
        if isinstance(field, DnType):
            yield Class(DnType.format_name(field.class_, namespace=field.namespace)), ih.address


def extract_insn_namespace_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Namespace, Address]]:
    """parse instruction namespace features"""
    if ih.inner.opcode in (
        OpCodes.Call,
        OpCodes.Callvirt,
        OpCodes.Jmp,
        OpCodes.Ldvirtftn,
        OpCodes.Ldftn,
        OpCodes.Newobj,
    ):
        # method call - includes managed methods (MethodDef, TypeRef) and properties (MethodSemantics, TypeRef)
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
        field: Optional[DnType] = get_fields(fh.ctx).get(ih.inner.operand.value, None)
        if isinstance(field, DnType) and field.namespace is not None:
            yield Namespace(field.namespace), ih.address


def extract_insn_number_features(fh, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction number features"""
    if ih.inner.is_ldc():
        yield Number(ih.inner.get_ldc()), ih.address


def extract_insn_string_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction string features"""
    if not ih.inner.is_ldstr():
        return

    if not isinstance(ih.inner.operand, StringToken):
        return

    user_string: Optional[str] = read_dotnet_user_string(fh.ctx["pe"], ih.inner.operand)
    if user_string is None:
        return

    yield String(user_string), ih.address


def extract_unmanaged_call_characteristic_features(
    fh: FunctionHandle, bb: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Characteristic, Address]]:
    if ih.inner.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    row: Union[str, InvalidToken, dnfile.base.MDTableRow] = resolve_dotnet_token(fh.ctx["pe"], ih.inner.operand)
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
