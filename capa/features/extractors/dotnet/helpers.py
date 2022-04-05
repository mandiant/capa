from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dnfile.mdtable import MemberRefRow
    from dnfile.mdtable import MethodDefRow
    from dnfile import dnPE

import dnfile
from dnfile.enums import MetadataTables
from dncil.cil.body import CilMethodBody
from dncil.clr.token import Token, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase

# key indexes to dotnet metadata tables
DOTNET_META_TABLES_BY_INDEX = {table.value: table.name for table in MetadataTables}


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe: dnfile.dnPE, row: MethodDefRow):
        """ """
        self.pe = pe
        self.rva = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        """ """
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.rva), n)
        self.rva += n
        return data

    def tell(self):
        """ """
        return self.rva

    def seek(self, rva):
        """ """
        self.rva = rva

    def get_token(self, value, is_str=False):
        """ """
        token = Token(value)

        if is_str:
            return self.pe.net.user_strings.get_us(token.rid).value

        table_name = DOTNET_META_TABLES_BY_INDEX.get(token.table, "")
        if not table_name:
            # table_index is not valid
            return InvalidToken(token.value)

        table = getattr(self.pe.net.mdtables, table_name, None)
        if table is None:
            # table index is valid but table is not present
            return InvalidToken(token.value)

        try:
            return table.rows[token.rid - 1]
        except IndexError:
            # table index is valid but row index is not valid
            return InvalidToken(token.value)


def read_dotnet_method_body(pe: dnPE, row: MethodDefRow) -> CilMethodBody:
    """ """
    return CilMethodBody(DnfileMethodBodyReader(pe, row))


def get_imported_class_name(row: MemberRefRow) -> str:
    """ """
    return f"{row.Class.row.TypeNamespace}.{row.Class.row.TypeName}"
