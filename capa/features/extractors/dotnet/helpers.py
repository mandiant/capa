from __future__ import annotations

from typing import Any, Dict, Tuple, Iterator
from itertools import chain

import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase

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


def generate_dotnet_token(table: int, rid: int) -> int:
    return ((table & 0xFF) << Token.TABLE_SHIFT) | (rid & Token.RID_MASK)


def resolve_dotnet_token(pe: dnfile.dnPE, token: Token) -> Any:
    """map generic token to string or table row"""
    if isinstance(token, StringToken):
        return pe.net.user_strings.get_us(token.rid).value

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


def read_dotnet_method_body(pe: dnfile.dnPE, row: dnfile.mdtable.MethodDefRow) -> CilMethodBody:
    """read dotnet method body"""
    return CilMethodBody(DnfileMethodBodyReader(pe, row))


def get_class_import_name(row: dnfile.mdtable.MemberRefRow) -> str:
    """get class import name from TypeRef table"""
    if not isinstance(row.Class.row, dnfile.mdtable.TypeRefRow):
        return ""
    # like System.IO.File
    return f"{row.Class.row.TypeNamespace}.{row.Class.row.TypeName}"


def get_class_imports(pe: dnfile.dnPE) -> Iterator[Tuple[int, str]]:
    """get class imports from MemberRef table

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
    if not hasattr(pe.net.mdtables, "MemberRef"):
        return

    for (rid, row) in enumerate(pe.net.mdtables.MemberRef):
        if not isinstance(row.Class.row, (dnfile.mdtable.TypeRefRow,)):
            continue

        token = generate_dotnet_token(dnfile.enums.MetadataTables.MemberRef.value, rid + 1)
        # like System.IO.File::OpenRead
        imp = f"{get_class_import_name(row)}::{row.Name}"

        yield token, imp


def get_native_imports(pe: dnfile.dnPE) -> Iterator[Tuple[int, str]]:
    """get native p/invoke calls from ImplMap table

    see https://www.ntcore.com/files/dotnetformat.htm

    28 - ImplMap Table
        ImplMap table holds information about unmanaged methods that can be reached from managed code, using PInvoke dispatch
            MemberForwarded (index into the Field or MethodDef table; more precisely, a MemberForwarded coded index)
            ImportName (index into the String heap)
            ImportScope (index into the ModuleRef table)
    """
    if not hasattr(pe.net.mdtables, "ImplMap"):
        return

    for row in pe.net.mdtables.ImplMap:
        dll: str = row.ImportScope.row.Name
        symbol: str = row.ImportName

        # ECMA says "Each row of the ImplMap table associates a row in the MethodDef table (MemberForwarded) with the
        # name of a routine (ImportName) in some unmanaged DLL (ImportScope)"; so we calculate and map the MemberForwarded
        # MethodDef table token to help us later record native import method calls made from CIL
        token: int = generate_dotnet_token(row.MemberForwarded.table.number, row.MemberForwarded.row_index)

        # like Kernel32.dll
        if dll and "." in dll:
            dll = dll.split(".")[0]

        # like kernel32.CreateFileA
        imp: str = f"{dll}.{symbol}"

        yield token, imp


def get_dotnet_imports(pe: dnfile.dnPE) -> Dict[int, str]:
    """get class imports and native p/invoke calls"""
    imps: Dict[int, str] = {}

    for (token, imp) in chain(get_class_imports(pe), get_native_imports(pe)):
        imps[token] = imp

    return imps


def get_dotnet_methods(pe: dnfile.dnPE) -> Iterator[CilMethodBody]:
    """get managed methods from MethodDef table"""
    if not hasattr(pe.net.mdtables, "MethodDef"):
        return

    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            # skip methods that do not have a method body
            continue

        try:
            body: CilMethodBody = read_dotnet_method_body(pe, row)
        except MethodBodyFormatError:
            # TODO
            continue

        yield body
