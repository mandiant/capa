# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
import logging
import collections
from typing import Any, Optional

from vivisect import VivWorkspace
from vivisect.const import XR_TO, REF_CODE

logger = logging.getLogger(__name__)

STT_FUNC = 0x2
STT_GNU_IFUNC = 0xA


def get_coderef_from(vw: VivWorkspace, va: int) -> Optional[int]:
    """
    return first code `tova` whose origin is the specified va
    return None if no code reference is found
    """
    xrefs = vw.getXrefsFrom(va, REF_CODE)
    if len(xrefs) > 0:
        return xrefs[0][XR_TO]
    else:
        return None


def get_elf_symbol_functions(parsedbin: Any) -> dict[int, list[str]]:
    """index elf function symbol names by address."""
    symbol_functions: dict[int, list[str]] = collections.defaultdict(list)
    try:
        from capa.features.extractors.elf import SymTab

        symtab = SymTab.from_viv(parsedbin)
        if symtab:
            for symbol in symtab.get_symbols():
                if (symbol.info & 0xF) in (STT_FUNC, STT_GNU_IFUNC):
                    try:
                        name = symtab.get_name(symbol)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if name:
                        symbol_functions[symbol.value].append(name)
    except (ValueError, struct.error, IndexError, AttributeError) as e:
        logger.debug("failed to parse elf symbol table: %s", e)

    return symbol_functions
