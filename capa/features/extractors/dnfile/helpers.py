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
from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase

from capa.features.common import FeatureAccess
from capa.features.extractors.dnfile.types import DnType, DnUnmanagedMethod

logger = logging.getLogger(__name__)


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe: dnfile.dnPE, row: dnfile.mdtable.MethodDefRow):
        self.pe: dnfile.dnPE = pe
        self.offset: int = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n: int) -> bytes:
        data: bytes = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int) -> int:
        self.offset = offset
        return self.offset


def resolve_dotnet_token(pe: dnfile.dnPE, token: Token) -> Union[dnfile.base.MDTableRow, InvalidToken, str]:
    """map generic token to string or table row"""
    assert pe.net is not None
    assert pe.net.mdtables is not None

    if isinstance(token, StringToken):
        user_string: Optional[str] = read_dotnet_user_string(pe, token)
        if user_string is None:
            return InvalidToken(token.value)
        return user_string

    table: Optional[dnfile.base.ClrMetaDataTable] = pe.net.mdtables.tables.get(token.table, None)
    if table is None:
        # table index is not valid
        return InvalidToken(token.value)

    try:
        return table.rows[token.rid - 1]
    except IndexError:
        # table index is valid but row index is not valid
        return InvalidToken(token.value)


def read_dotnet_method_body(pe: dnfile.dnPE, row: dnfile.mdtable.MethodDefRow) -> Optional[CilMethodBody]:
    """read dotnet method body"""
    try:
        return CilMethodBody(DnfileMethodBodyReader(pe, row))
    except MethodBodyFormatError as e:
        logger.debug("failed to parse managed method body @ 0x%08x (%s)", row.Rva, e)
        return None


def read_dotnet_user_string(pe: dnfile.dnPE, token: StringToken) -> Optional[str]:
    """read user string from #US stream"""
    assert pe.net is not None

    if pe.net.user_strings is None:
        # stream may not exist (seen in obfuscated .NET)
        logger.debug("#US stream does not exist for stream index 0x%08x", token.rid)
        return None

    try:
        user_string: Optional[dnfile.stream.UserString] = pe.net.user_strings.get_us(token.rid)
    except UnicodeDecodeError as e:
        logger.debug("failed to decode #US stream index 0x%08x (%s)", token.rid, e)
        return None

    if user_string is None:
        return None

    return user_string.value


def get_dotnet_managed_imports(pe: dnfile.dnPE) -> Iterator[DnType]:
    """get managed imports from MemberRef table

    see https://www.ntcore.com/files/dotnetformat.htm

    10 - MemberRef Table
        Each row represents an imported method
            Class (index into the TypeRef, ModuleRef, MethodDef, TypeSpec or TypeDef tables)
            Name (index into String heap)
    01 - TypeRef Table
        Each row represents an imported class, its namespace and the assembly which contains it
            TypeName (index into String heap)
            TypeNamespace (index into String heap)
    """
    for (rid, member_ref) in iter_dotnet_table(pe, dnfile.mdtable.MemberRef.number):
        assert isinstance(member_ref, dnfile.mdtable.MemberRefRow)

        if not isinstance(member_ref.Class.row, dnfile.mdtable.TypeRefRow):
            # only process class imports from TypeRef table
            continue

        token: int = calculate_dotnet_token_value(dnfile.mdtable.MemberRef.number, rid)
        access: Optional[str]

        # assume .NET imports starting with get_/set_ are used to access a property
        if member_ref.Name.startswith("get_"):
            access = FeatureAccess.READ
        elif member_ref.Name.startswith("set_"):
            access = FeatureAccess.WRITE
        else:
            access = None

        member_ref_name: str = member_ref.Name
        if member_ref_name.startswith(("get_", "set_")):
            # remove get_/set_ from MemberRef name
            member_ref_name = member_ref_name[4:]

        yield DnType(
            token,
            member_ref.Class.row.TypeName,
            namespace=member_ref.Class.row.TypeNamespace,
            member=member_ref_name,
            access=access,
        )


def get_dotnet_methoddef_property_accessors(pe: dnfile.dnPE) -> Iterator[Tuple[int, str]]:
    """get MethodDef methods used to access properties

    see https://www.ntcore.com/files/dotnetformat.htm

    24 - MethodSemantics Table
        Links Events and Properties to specific methods. For example one Event can be associated to more methods. A property uses this table to associate get/set methods.
            Semantics (a 2-byte bitmask of type MethodSemanticsAttributes)
            Method (index into the MethodDef table)
            Association (index into the Event or Property table; more precisely, a HasSemantics coded index)
    """
    for (rid, method_semantics) in iter_dotnet_table(pe, dnfile.mdtable.MethodSemantics.number):
        assert isinstance(method_semantics, dnfile.mdtable.MethodSemanticsRow)

        if method_semantics.Association.row is None:
            logger.debug("MethodSemantics[0x%X] Association row is None", rid)
            continue

        if isinstance(method_semantics.Association.row, dnfile.mdtable.EventRow):
            # ignore events
            logger.debug("MethodSemantics[0x%X] ignoring Event", rid)
            continue

        if method_semantics.Method.table is None:
            logger.debug("MethodSemantics[0x%X] Method table is None", rid)
            continue

        token: int = calculate_dotnet_token_value(
            method_semantics.Method.table.number, method_semantics.Method.row_index
        )

        if method_semantics.Semantics.msSetter:
            yield token, FeatureAccess.WRITE
        elif method_semantics.Semantics.msGetter:
            yield token, FeatureAccess.READ


def get_dotnet_managed_methods(pe: dnfile.dnPE) -> Iterator[DnType]:
    """get managed method names from TypeDef table

    see https://www.ntcore.com/files/dotnetformat.htm

    02 - TypeDef Table
        Each row represents a class in the current assembly.
            TypeName (index into String heap)
            TypeNamespace (index into String heap)
            MethodList (index into MethodDef table; it marks the first of a contiguous run of Methods owned by this Type)
    """
    accessor_map: Dict[int, str] = {}
    for (methoddef, methoddef_access) in get_dotnet_methoddef_property_accessors(pe):
        accessor_map[methoddef] = methoddef_access

    for (rid, typedef) in iter_dotnet_table(pe, dnfile.mdtable.TypeDef.number):
        assert isinstance(typedef, dnfile.mdtable.TypeDefRow)

        for (idx, method) in enumerate(typedef.MethodList):
            if method.table is None:
                logger.debug("TypeDef[0x%X] MethodList[0x%X] table is None", rid, idx)
                continue
            if method.row is None:
                logger.debug("TypeDef[0x%X] MethodList[0x%X] row is None", rid, idx)
                continue

            token: int = calculate_dotnet_token_value(method.table.number, method.row_index)
            access: Optional[str] = accessor_map.get(token, None)

            method_name: str = method.row.Name
            if method_name.startswith(("get_", "set_")):
                # remove get_/set_
                method_name = method_name[4:]

            yield DnType(token, typedef.TypeName, namespace=typedef.TypeNamespace, member=method_name, access=access)


def get_dotnet_fields(pe: dnfile.dnPE) -> Iterator[DnType]:
    """get fields from TypeDef table

    see https://www.ntcore.com/files/dotnetformat.htm

    02 - TypeDef Table
        Each row represents a class in the current assembly.
            TypeName (index into String heap)
            TypeNamespace (index into String heap)
            FieldList (index into Field table; it marks the first of a contiguous run of Fields owned by this Type)
    """
    for (rid, typedef) in iter_dotnet_table(pe, dnfile.mdtable.TypeDef.number):
        assert isinstance(typedef, dnfile.mdtable.TypeDefRow)

        for (idx, field) in enumerate(typedef.FieldList):
            if field.table is None:
                logger.debug("TypeDef[0x%X] FieldList[0x%X] table is None", rid, idx)
                continue
            if field.row is None:
                logger.debug("TypeDef[0x%X] FieldList[0x%X] row is None", rid, idx)
                continue
            token: int = calculate_dotnet_token_value(field.table.number, field.row_index)
            yield DnType(token, typedef.TypeName, namespace=typedef.TypeNamespace, member=field.row.Name)


def get_dotnet_managed_method_bodies(pe: dnfile.dnPE) -> Iterator[Tuple[int, CilMethodBody]]:
    """get managed methods from MethodDef table"""
    for (rid, method_def) in iter_dotnet_table(pe, dnfile.mdtable.MethodDef.number):
        assert isinstance(method_def, dnfile.mdtable.MethodDefRow)

        if not method_def.ImplFlags.miIL or any((method_def.Flags.mdAbstract, method_def.Flags.mdPinvokeImpl)):
            # skip methods that do not have a method body
            continue

        body: Optional[CilMethodBody] = read_dotnet_method_body(pe, method_def)
        if body is None:
            logger.debug("MethodDef[0x%X] method body is None", rid)
            continue

        token: int = calculate_dotnet_token_value(dnfile.mdtable.MethodDef.number, rid)
        yield token, body


def get_dotnet_unmanaged_imports(pe: dnfile.dnPE) -> Iterator[DnUnmanagedMethod]:
    """get unmanaged imports from ImplMap table

    see https://www.ntcore.com/files/dotnetformat.htm

    28 - ImplMap Table
        ImplMap table holds information about unmanaged methods that can be reached from managed code, using PInvoke dispatch
            MemberForwarded (index into the Field or MethodDef table; more precisely, a MemberForwarded coded index)
            ImportName (index into the String heap)
            ImportScope (index into the ModuleRef table)
    """
    for (rid, impl_map) in iter_dotnet_table(pe, dnfile.mdtable.ImplMap.number):
        assert isinstance(impl_map, dnfile.mdtable.ImplMapRow)

        module: str
        if impl_map.ImportScope.row is None:
            logger.debug("ImplMap[0x%X] ImportScope row is None", rid)
            module = ""
        else:
            module = impl_map.ImportScope.row.Name
        method: str = impl_map.ImportName

        member_forward_table: int
        if impl_map.MemberForwarded.table is None:
            logger.debug("ImplMap[0x%X] MemberForwarded table is None", rid)
            continue
        else:
            member_forward_table = impl_map.MemberForwarded.table.number
        member_forward_row: int = impl_map.MemberForwarded.row_index

        # ECMA says "Each row of the ImplMap table associates a row in the MethodDef table (MemberForwarded) with the
        # name of a routine (ImportName) in some unmanaged DLL (ImportScope)"; so we calculate and map the MemberForwarded
        # MethodDef table token to help us later record native import method calls made from CIL
        token: int = calculate_dotnet_token_value(member_forward_table, member_forward_row)

        # like Kernel32.dll
        if module and "." in module:
            module = module.split(".")[0]

        # like kernel32.CreateFileA
        yield DnUnmanagedMethod(token, module, method)


def get_dotnet_types(pe: dnfile.dnPE) -> Iterator[DnType]:
    """get .NET types from TypeDef and TypeRef tables"""
    for (rid, typedef) in iter_dotnet_table(pe, dnfile.mdtable.TypeDef.number):
        assert isinstance(typedef, dnfile.mdtable.TypeDefRow)

        typedef_token: int = calculate_dotnet_token_value(dnfile.mdtable.TypeDef.number, rid)
        yield DnType(typedef_token, typedef.TypeName, namespace=typedef.TypeNamespace)

    for (rid, typeref) in iter_dotnet_table(pe, dnfile.mdtable.TypeRef.number):
        assert isinstance(typeref, dnfile.mdtable.TypeRefRow)

        typeref_token: int = calculate_dotnet_token_value(dnfile.mdtable.TypeRef.number, rid)
        yield DnType(typeref_token, typeref.TypeName, namespace=typeref.TypeNamespace)


def calculate_dotnet_token_value(table: int, rid: int) -> int:
    return ((table & 0xFF) << Token.TABLE_SHIFT) | (rid & Token.RID_MASK)


def is_dotnet_mixed_mode(pe: dnfile.dnPE) -> bool:
    assert pe.net is not None
    assert pe.net.Flags is not None

    return not bool(pe.net.Flags.CLR_ILONLY)


def iter_dotnet_table(pe: dnfile.dnPE, table_index: int) -> Iterator[Tuple[int, dnfile.base.MDTableRow]]:
    assert pe.net is not None
    assert pe.net.mdtables is not None

    for (rid, row) in enumerate(pe.net.mdtables.tables.get(table_index, [])):
        # .NET tables are 1-indexed
        yield rid + 1, row
