# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Tuple, Iterator, Optional

import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase

from capa.features.common import FeatureAccess

logger = logging.getLogger(__name__)

# key indexes to dotnet metadata tables
DOTNET_META_TABLES_BY_INDEX = {table.value: table.name for table in dnfile.enums.MetadataTables}


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


class DnType(object):
    def __init__(self, token: int, class_: str, namespace: str = "", member: str = "", access: Optional[str] = None):
        self.token = token
        self.access = access
        self.namespace = namespace
        self.class_ = class_
        self.member = member

    def __hash__(self):
        return hash((self.token, self.access, self.namespace, self.class_, self.member))

    def __eq__(self, other):
        return (
            self.token == other.token
            and self.access == other.access
            and self.namespace == other.namespace
            and self.class_ == other.class_
            and self.member == other.member
        )

    def __str__(self):
        return DnType.format_name(self.class_, namespace=self.namespace, member=self.member)

    def __repr__(self):
        return str(self)

    @staticmethod
    def format_name(class_: str, namespace: str = "", member: str = ""):
        # like File::OpenRead
        name: str = f"{class_}::{member}" if member else class_
        if namespace:
            # like System.IO.File::OpenRead
            name = f"{namespace}.{name}"
        return name


class DnUnmanagedMethod:
    def __init__(self, token: int, module: str, method: str):
        self.token: int = token
        self.module: str = module
        self.method: str = method

    def __hash__(self):
        return hash((self.token, self.module, self.method))

    def __eq__(self, other):
        return self.token == other.token and self.module == other.module and self.method == other.method

    def __str__(self):
        return DnUnmanagedMethod.format_name(self.module, self.method)

    def __repr__(self):
        return str(self)

    @staticmethod
    def format_name(module, method):
        return f"{module}.{method}"


def resolve_dotnet_token(pe: dnfile.dnPE, token: Token) -> Any:
    """map generic token to string or table row"""
    if isinstance(token, StringToken):
        user_string: Optional[str] = read_dotnet_user_string(pe, token)
        if user_string is None:
            return InvalidToken(token.value)
        return user_string

    table_name: str = DOTNET_META_TABLES_BY_INDEX.get(token.table, "")
    if not table_name:
        # table_index is not valid
        return InvalidToken(token.value)

    table: Any = getattr(pe.net.mdtables, table_name, None)
    if table is None:
        # table index is valid but table is not present
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
        logger.warning("failed to parse managed method body @ 0x%08x (%s)" % (row.Rva, e))
        return None


def read_dotnet_user_string(pe: dnfile.dnPE, token: StringToken) -> Optional[str]:
    """read user string from #US stream"""
    try:
        user_string: Optional[dnfile.stream.UserString] = pe.net.user_strings.get_us(token.rid)
    except UnicodeDecodeError as e:
        logger.warning("failed to decode #US stream index 0x%08x (%s)" % (token.rid, e))
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
    for (rid, row) in enumerate(iter_dotnet_table(pe, "MemberRef")):
        if not isinstance(row.Class.row, dnfile.mdtable.TypeRefRow):
            continue
        token: int = calculate_dotnet_token_value(pe.net.mdtables.MemberRef.number, rid + 1)
        yield DnType(token, row.Class.row.TypeName, namespace=row.Class.row.TypeNamespace, member=row.Name)


def get_dotnet_managed_methods(pe: dnfile.dnPE) -> Iterator[DnType]:
    """get managed method names from TypeDef table

    see https://www.ntcore.com/files/dotnetformat.htm

    02 - TypeDef Table
        Each row represents a class in the current assembly.
            TypeName (index into String heap)
            TypeNamespace (index into String heap)
            MethodList (index into MethodDef table; it marks the first of a continguous run of Methods owned by this Type)
    """
    for row in iter_dotnet_table(pe, "TypeDef"):
        for index in row.MethodList:
            token = calculate_dotnet_token_value(index.table.number, index.row_index)
            yield DnType(token, row.TypeName, namespace=row.TypeNamespace, member=index.row.Name)


def get_dotnet_fields(pe: dnfile.dnPE) -> Iterator[DnType]:
    """get fields from TypeDef table"""
    for row in iter_dotnet_table(pe, "TypeDef"):
        for index in row.FieldList:
            token = calculate_dotnet_token_value(index.table.number, index.row_index)
            yield DnType(token, row.TypeName, namespace=row.TypeNamespace, member=index.row.Name)


def get_dotnet_property_map(
    pe: dnfile.dnPE, property_row: dnfile.mdtable.PropertyRow
) -> Optional[dnfile.mdtable.TypeDefRow]:
    """get property map from PropertyMap table

    see https://www.ntcore.com/files/dotnetformat.htm

    21 - PropertyMap Table
        List of Properties owned by a specific class.
            Parent (index into the TypeDef table)
            PropertyList (index into Property table). It marks the first of a contiguous run of Properties owned by Parent. The run continues to the smaller of:
                the last row of the Property table
                the next run of Properties, found by inspecting the PropertyList of the next row in this PropertyMap table
    """
    for row in iter_dotnet_table(pe, "PropertyMap"):
        for index in row.PropertyList:
            if index.row.Name == property_row.Name:
                return row.Parent.row
    return None


def get_dotnet_properties(pe: dnfile.dnPE) -> Iterator[DnType]:
    """get property from MethodSemantics table

    see https://www.ntcore.com/files/dotnetformat.htm

    24 - MethodSemantics Table
        Links Events and Properties to specific methods. For example one Event can be associated to more methods. A property uses this table to associate get/set methods.
            Semantics (a 2-byte bitmask of type MethodSemanticsAttributes)
            Method (index into the MethodDef table)
            Association (index into the Event or Property table; more precisely, a HasSemantics coded index)
    """
    for row in iter_dotnet_table(pe, "MethodSemantics"):
        typedef_row = get_dotnet_property_map(pe, row.Association.row)
        if typedef_row is None:
            continue

        token = calculate_dotnet_token_value(row.Method.table.number, row.Method.row_index)

        if row.Semantics.msSetter:
            access = FeatureAccess.WRITE
        elif row.Semantics.msGetter:
            access = FeatureAccess.READ
        else:
            access = None

        yield DnType(
            token,
            typedef_row.TypeName,
            access=access,
            namespace=typedef_row.TypeNamespace,
            member=row.Association.row.Name,
        )


def get_dotnet_managed_method_bodies(pe: dnfile.dnPE) -> Iterator[Tuple[int, CilMethodBody]]:
    """get managed methods from MethodDef table"""
    if not hasattr(pe.net.mdtables, "MethodDef"):
        return

    for (rid, row) in enumerate(pe.net.mdtables.MethodDef):
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            # skip methods that do not have a method body
            continue

        body: Optional[CilMethodBody] = read_dotnet_method_body(pe, row)
        if body is None:
            continue

        token: int = calculate_dotnet_token_value(dnfile.enums.MetadataTables.MethodDef.value, rid + 1)
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
    for row in iter_dotnet_table(pe, "ImplMap"):
        module: str = row.ImportScope.row.Name
        method: str = row.ImportName

        # ECMA says "Each row of the ImplMap table associates a row in the MethodDef table (MemberForwarded) with the
        # name of a routine (ImportName) in some unmanaged DLL (ImportScope)"; so we calculate and map the MemberForwarded
        # MethodDef table token to help us later record native import method calls made from CIL
        token: int = calculate_dotnet_token_value(row.MemberForwarded.table.number, row.MemberForwarded.row_index)

        # like Kernel32.dll
        if module and "." in module:
            module = module.split(".")[0]

        # like kernel32.CreateFileA
        yield DnUnmanagedMethod(token, module, method)


def calculate_dotnet_token_value(table: int, rid: int) -> int:
    return ((table & 0xFF) << Token.TABLE_SHIFT) | (rid & Token.RID_MASK)


def is_dotnet_table_valid(pe: dnfile.dnPE, table_name: str) -> bool:
    return bool(getattr(pe.net.mdtables, table_name, None))


def is_dotnet_mixed_mode(pe: dnfile.dnPE) -> bool:
    return not bool(pe.net.Flags.CLR_ILONLY)


def iter_dotnet_table(pe: dnfile.dnPE, name: str) -> Iterator[Any]:
    if not is_dotnet_table_valid(pe, name):
        return
    for row in getattr(pe.net.mdtables, name):
        yield row
