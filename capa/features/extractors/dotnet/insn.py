from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Union, Generator

if TYPE_CHECKING:
    from dncil.cil.instruction import Instruction
    from dncil.cil.body import CilMethodBody

from dncil.clr.token import StringToken
from dncil.cil.opcode import OpCodes

import capa.features.extractors.helpers
from capa.features.insn import API, Number
from capa.features.common import String
from capa.features.extractors.dotnet.helpers import get_dotnet_imports


def get_imports(ctx):
    """ """
    if "imports_cache" not in ctx:
        ctx["imports_cache"] = get_dotnet_imports(ctx["pe"])
    return ctx["imports_cache"]


def extract_insn_api_features(
    f: CilMethodBody, bb: CilMethodBody, insn: Instruction
) -> Generator[Tuple[API, int], None, None]:
    """parse instruction API features"""
    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    name = get_imports(f.ctx).get(insn.operand.value, "")
    if not name:
        return

    if "::" in name:
        # like System.IO.File::OpenRead
        yield API(name), insn.offset
    else:
        # like kernel32.CreateFileA
        dll, _, symbol = name.rpartition(".")
        for name_variant in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield API(name_variant), insn.offset


def extract_insn_number_features(
    f: CilMethodBody, bb: CilMethodBody, insn: Instruction
) -> Generator[Tuple[Number, int], None, None]:
    """parse instruction number features"""
    if insn.is_ldc():
        yield Number(insn.get_ldc()), insn.offset


def extract_insn_string_features(
    f: CilMethodBody, bb: CilMethodBody, insn: Instruction
) -> Generator[Tuple[String, int], None, None]:
    """parse instruction string features"""
    if not insn.is_ldstr():
        return

    if not isinstance(insn.operand, StringToken):
        return

    user_string = f.ctx["pe"].net.user_strings.get_us(insn.operand.rid).value
    yield String(user_string), insn.offset


def extract_features(
    f: CilMethodBody, bb: CilMethodBody, insn: Instruction
) -> Generator[Tuple[Union[API, String, Number], int], None, None]:
    """extract instruction features"""
    for inst_handler in INSTRUCTION_HANDLERS:
        for (feature, ea) in inst_handler(f, bb, insn):
            yield feature, ea


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_string_features,
)


def main(args):
    """ """
    pe: dnPE = dnfile.dnPE(args.path)

    ctx = {}
    ctx["pe"] = pe

    features: List[Any] = []
    for method in get_dotnet_methods(pe):
        setattr(method, "ctx", ctx)
        for insn in method.instructions:
            features.extend(list(extract_features(method, method, insn)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    """ """
    import argparse

    import dnfile

    from capa.features.extractors.dotnet.helpers import get_dotnet_methods

    parser = argparse.ArgumentParser(prog="parse instruction features from .NET PE")
    parser.add_argument("path", type=str, help="full path to .NET PE")

    main(parser.parse_args())
