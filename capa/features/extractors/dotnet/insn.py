from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Tuple, Union, Callable, Generator, Any

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


def get_imports(ctx):
    """ """
    if "imports_cache" not in ctx:
        ctx["imports_cache"] = capa.features.extractors.dotnet.helpers.get_imports(ctx["pe"])
    return ctx["imports_cache"]


def extract_insn_api_features(f: CilMethodBody, insn: Instruction) -> Generator[Tuple[API, int], None, None]:
    """parse instruction API features"""
    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    name = get_imports(f.ctx).get(insn.operand.value, "")
    if not name:
        return

    if "::" in name:
        yield API(name), insn.offset
    else:
        dll, _, symbol = name.rpartition(".")
        for name_variant in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield API(name_variant), insn.offset


def extract_insn_number_features(f: CilMethodBody, insn: Instruction) -> Generator[Tuple[Number, int], None, None]:
    """parse instruction number features"""
    if insn.is_ldc():
        yield Number(insn.get_ldc()), insn.offset


def extract_insn_string_features(f: CilMethodBody, insn: Instruction) -> Generator[Tuple[String, int], None, None]:
    """parse instruction string features"""
    if insn.is_ldstr():
        user_string = capa.features.extractors.dotnet.helpers.resolve_token(f.ctx["pe"], insn.operand)
        yield String(user_string), insn.offset


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
    pe: dnPE = dnfile.dnPE(args.path)

    # data structure shared across functions yielded here.
    # useful for caching analysis relevant across a single workspace.
    ctx = {}
    ctx["pe"] = pe

    features: List[Any] = []
    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            continue

        try:
            body: CilMethodBody = get_method_body(pe, row)
        except MethodBodyFormatError as e:
            print(e)
            continue

        setattr(body, "ctx", ctx)

        for insn in body.instructions:
            features.extend(list(extract_features(body, insn)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    """ """
    import argparse

    from capa.features.extractors.dotnet.helpers import get_method_body

    parser = argparse.ArgumentParser(prog="parse instruction features from .NET PE")
    parser.add_argument("path", type=str, help="full path to .NET PE")

    main(parser.parse_args())
