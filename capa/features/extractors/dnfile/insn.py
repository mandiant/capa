# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Tuple, Union, Iterator, Optional

if TYPE_CHECKING:
    from capa.features.extractors.dnfile.extractor import DnFileFeatureExtractorCache

import dnfile
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.opcode import OpCodes

import capa.features.extractors.helpers
from capa.features.insn import API, Number, Property
from capa.features.common import Class, String, Feature, Namespace, FeatureAccess, Characteristic
from capa.features.address import Address
from capa.features.extractors.dnfile.types import DnType, DnUnmanagedMethod
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.dnfile.helpers import (
    resolve_dotnet_token,
    read_dotnet_user_string,
    calculate_dotnet_token_value,
)

logger = logging.getLogger(__name__)


def get_callee(
    pe: dnfile.dnPE, cache: DnFileFeatureExtractorCache, token: Token
) -> Optional[Union[DnType, DnUnmanagedMethod]]:
    """map .NET token to un/managed (generic) method"""
    token_: int
    if token.table == dnfile.mdtable.MethodSpec.number:
        # map MethodSpec to MethodDef or MemberRef
        row: Union[dnfile.base.MDTableRow, InvalidToken, str] = resolve_dotnet_token(pe, token)
        assert isinstance(row, dnfile.mdtable.MethodSpecRow)

        if row.Method.table is None:
            logger.debug("MethodSpec[0x%X] Method table is None", token.rid)
            return None

        token_ = calculate_dotnet_token_value(row.Method.table.number, row.Method.row_index)
    else:
        token_ = token.value

    callee: Optional[Union[DnType, DnUnmanagedMethod]] = cache.get_import(token_)
    if callee is None:
        # we must check unmanaged imports before managed methods because we map forwarded managed methods
        # to their unmanaged imports; we prefer a forwarded managed method be mapped to its unmanaged import for analysis
        callee = cache.get_native_import(token_)
        if callee is None:
            callee = cache.get_method(token_)
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

    callee: Optional[Union[DnType, DnUnmanagedMethod]] = get_callee(fh.ctx["pe"], fh.ctx["cache"], ih.inner.operand)
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
        callee: Optional[Union[DnType, DnUnmanagedMethod]] = get_callee(fh.ctx["pe"], fh.ctx["cache"], ih.inner.operand)
        if isinstance(callee, DnType):
            if callee.access is not None:
                name = str(callee)
                access = callee.access

    elif ih.inner.opcode in (OpCodes.Ldfld, OpCodes.Ldflda, OpCodes.Ldsfld, OpCodes.Ldsflda):
        # property read via Field
        read_field: Optional[Union[DnType, DnUnmanagedMethod]] = fh.ctx["cache"].get_field(ih.inner.operand.value)
        if read_field is not None:
            name = str(read_field)
            access = FeatureAccess.READ

    elif ih.inner.opcode in (OpCodes.Stfld, OpCodes.Stsfld):
        # property write via Field
        write_field: Optional[Union[DnType, DnUnmanagedMethod]] = fh.ctx["cache"].get_field(ih.inner.operand.value)
        if write_field is not None:
            name = str(write_field)
            access = FeatureAccess.WRITE

    if name is not None:
        if access is not None:
            yield Property(name, access=access), ih.address
        yield Property(name), ih.address


def extract_insn_namespace_class_features(
    fh: FunctionHandle, bh, ih: InsnHandle
) -> Iterator[Tuple[Union[Namespace, Class], Address]]:
    """parse instruction namespace and class features"""
    type_: Optional[Union[DnType, DnUnmanagedMethod]] = None

    if ih.inner.opcode in (
        OpCodes.Call,
        OpCodes.Callvirt,
        OpCodes.Jmp,
        OpCodes.Ldvirtftn,
        OpCodes.Ldftn,
        OpCodes.Newobj,
    ):
        # method call - includes managed methods (MethodDef, TypeRef) and properties (MethodSemantics, TypeRef)
        type_ = get_callee(fh.ctx["pe"], fh.ctx["cache"], ih.inner.operand)

    elif ih.inner.opcode in (
        OpCodes.Ldfld,
        OpCodes.Ldflda,
        OpCodes.Ldsfld,
        OpCodes.Ldsflda,
        OpCodes.Stfld,
        OpCodes.Stsfld,
    ):
        # field access
        type_ = fh.ctx["cache"].get_field(ih.inner.operand.value)

    # ECMA 335 VI.C.4.10
    elif ih.inner.opcode in (
        OpCodes.Initobj,
        OpCodes.Box,
        OpCodes.Castclass,
        OpCodes.Cpobj,
        OpCodes.Isinst,
        OpCodes.Ldelem,
        OpCodes.Ldelema,
        OpCodes.Ldobj,
        OpCodes.Mkrefany,
        OpCodes.Newarr,
        OpCodes.Refanyval,
        OpCodes.Sizeof,
        OpCodes.Stobj,
        OpCodes.Unbox,
        OpCodes.Constrained,
        OpCodes.Stelem,
        OpCodes.Unbox_Any,
    ):
        # type access
        type_ = fh.ctx["cache"].get_type(ih.inner.operand.value)

    if isinstance(type_, DnType):
        yield Class(DnType.format_name(type_.class_, namespace=type_.namespace)), ih.address
        if type_.namespace:
            yield Namespace(type_.namespace), ih.address


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

    if len(user_string) >= 4:
        yield String(user_string), ih.address


def extract_unmanaged_call_characteristic_features(
    fh: FunctionHandle, bb: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Characteristic, Address]]:
    if ih.inner.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp):
        return

    row: Union[str, InvalidToken, dnfile.base.MDTableRow] = resolve_dotnet_token(fh.ctx["pe"], ih.inner.operand)
    if not isinstance(row, dnfile.mdtable.MethodDefRow):
        return

    if any((row.Flags.mdPinvokeImpl, row.ImplFlags.miUnmanaged, row.ImplFlags.miNative)):
        yield Characteristic("unmanaged call"), ih.address


def extract_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract instruction features"""
    for inst_handler in INSTRUCTION_HANDLERS:
        for feature, addr in inst_handler(fh, bbh, ih):
            assert isinstance(addr, Address)
            yield feature, addr


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_property_features,
    extract_insn_number_features,
    extract_insn_string_features,
    extract_insn_namespace_class_features,
    extract_unmanaged_call_characteristic_features,
)
