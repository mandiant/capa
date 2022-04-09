# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Tuple, Iterator, Optional
from itertools import chain

from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle

if TYPE_CHECKING:
    from dncil.cil.instruction import Instruction
    from dncil.cil.body import CilMethodBody
    from capa.features.common import Feature
    from capa.features.address import Address

from dncil.clr.token import StringToken
from dncil.cil.opcode import OpCodes

import capa.features.extractors.helpers
from capa.features.insn import API, Number
from capa.features.common import String
from capa.features.extractors.dnfile.helpers import (
    read_dotnet_user_string,
    get_dotnet_managed_imports,
    get_dotnet_unmanaged_imports,
)


def get_imports(ctx: Dict) -> Dict:
    if "imports_cache" not in ctx:
        ctx["imports_cache"] = {
            token: imp
            for (token, imp) in chain(get_dotnet_managed_imports(ctx["pe"]), get_dotnet_unmanaged_imports(ctx["pe"]))
        }
    return ctx["imports_cache"]


def extract_insn_api_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction API features"""
    f: CilMethodBody = fh.inner
    insn: Instruction = ih.inner

    if insn.opcode not in (OpCodes.Call, OpCodes.Callvirt, OpCodes.Jmp, OpCodes.Calli):
        return

    name: str = get_imports(f.ctx).get(insn.operand.value, "")
    if not name:
        return

    if "::" in name:
        # like System.IO.File::OpenRead
        yield API(name), ih.address
    else:
        # like kernel32.CreateFileA
        dll, _, symbol = name.rpartition(".")
        for name_variant in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield API(name_variant), ih.address


def extract_insn_number_features(fh, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction number features"""
    insn: Instruction = ih.inner

    if insn.is_ldc():
        yield Number(insn.get_ldc()), ih.address


def extract_insn_string_features(fh: FunctionHandle, bh, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction string features"""
    f: CilMethodBody = fh.inner
    insn: Instruction = ih.inner

    if not insn.is_ldstr():
        return

    if not isinstance(insn.operand, StringToken):
        return

    user_string: Optional[str] = read_dotnet_user_string(f.ctx["pe"], insn.operand)
    if user_string is None:
        return

    yield String(user_string), ih.address


def extract_features(f: FunctionHandle, bb: BBHandle, insn: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract instruction features"""
    for inst_handler in INSTRUCTION_HANDLERS:
        for (feature, addr) in inst_handler(f, bb, insn):
            yield feature, addr


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_string_features,
)
