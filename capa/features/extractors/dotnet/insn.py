from __future__ import annotations

from typing import TYPE_CHECKING, List, Tuple, Union, Callable, Generator

if TYPE_CHECKING:
    from dncil.cil.instruction import Instruction
    from dncil.cil.body import CilMethodBody

import dncil
import dnfile
from dncil.cil.error import MethodBodyFormatError
from dncil.cil.opcode import OpCodes

import capa.features.extractors.helpers
import capa.features.extractors.dotnet.helpers
from capa.features.insn import API, Number
from capa.features.common import String


def extract_insn_api_features(f: CilMethodBody, insn: Instruction) -> Generator[Tuple[API, int], None, None]:
    """parse instruction API features

    see https://www.ntcore.com/files/dotnetformat.htm

    10 - MemberRef Table
        Each row represents an imported method.
            Class (index into the TypeRef, ModuleRef, MethodDef, TypeSpec or TypeDef tables)
    01 - TypeRef Table
        Each row represents an imported class, its namespace and the assembly which contains it.
            TypeName (index into String heap)
            TypeNamespace (index into String heap)
    """
    if insn.opcode in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        if isinstance(insn.operand, dnfile.mdtable.MemberRefRow):
            if isinstance(insn.operand.Class.row, (dnfile.mdtable.TypeRefRow,)):
                class_name = capa.features.extractors.dotnet.helpers.get_imported_class_name(insn.operand)
                method_name = insn.operand.Name
                yield API(f"{class_name}::{method_name}"), insn.offset


def extract_insn_number_features(f: CilMethodBody, insn: Instruction) -> Generator[Tuple[Number, int], None, None]:
    """parse instruction number features"""
    if insn.is_ldc():
        yield Number(insn.get_ldc()), insn.offset


def extract_insn_string_features(f: CilMethodBody, insn: Instruction) -> Generator[Tuple[String, int], None, None]:
    """parse instruction string features"""
    if insn.is_ldstr():
        yield String(insn.operand), insn.offset


def extract_features(
    f: CilMethodBody, insn: Instruction
) -> Generator[Tuple[Union[API, String, Number], int], None, None]:
    """extract instruction features"""
    for inst_handler in INSTRUCTION_HANDLERS:
        for (feature, ea) in inst_handler(f, insn):
            yield feature, ea


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_string_features,
)


def main(args):
    """ """
    dn = dnfile.dnPE(args.path)

    features = []
    for row in dn.net.mdtables.MethodDef:
        if row.ImplFlags.miIL:
            try:
                body = read_dotnet_method_body(dn, row)
            except MethodBodyFormatError as e:
                print(e)
                continue

        for insn in body.instructions:
            features.extend(list(extract_features(body, insn)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    """ """
    import argparse

    from capa.features.extractors.dotnet.helpers import read_dotnet_method_body

    parser = argparse.ArgumentParser(prog="parse instruction features from .NET PE")
    parser.add_argument("path", type=str, help="full path to .NET PE")

    main(parser.parse_args())
