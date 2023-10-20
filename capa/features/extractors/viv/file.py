# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Tuple, Iterator

import PE.carve as pe_carve  # vivisect PE
import vivisect
import viv_utils
import viv_utils.flirt

import capa.features.insn
import capa.features.extractors.common
import capa.features.extractors.helpers
import capa.features.extractors.strings
from capa.features.file import Export, Import, Section, FunctionName
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, FileOffsetAddress, AbsoluteVirtualAddress


def extract_file_embedded_pe(buf, **kwargs) -> Iterator[Tuple[Feature, Address]]:
    for offset, _ in pe_carve.carve(buf, 1):
        yield Characteristic("embedded pe"), FileOffsetAddress(offset)


def get_first_vw_filename(vw: vivisect.VivWorkspace):
    # vivisect associates metadata with each file that its loaded into the workspace.
    # capa only loads a single file into each workspace.
    # so to access the metadata for the file in question, we can just take the first one.
    # otherwise, we'd have to pass around the module name of the file we're analyzing,
    # which is a pain.
    #
    # so this is a simplifying assumption.
    return next(iter(vw.filemeta.keys()))


def extract_file_export_names(vw: vivisect.VivWorkspace, **kwargs) -> Iterator[Tuple[Feature, Address]]:
    for va, _, name, _ in vw.getExports():
        yield Export(name), AbsoluteVirtualAddress(va)

    if vw.getMeta("Format") == "pe":
        pe = vw.parsedbin
        baseaddr = pe.IMAGE_NT_HEADERS.OptionalHeader.ImageBase
        for rva, _, forwarded_name in vw.getFileMeta(get_first_vw_filename(vw), "forwarders"):
            try:
                forwarded_name = forwarded_name.partition(b"\x00")[0].decode("ascii")
            except UnicodeDecodeError:
                continue

            forwarded_name = capa.features.extractors.helpers.reformat_forwarded_export_name(forwarded_name)
            va = baseaddr + rva
            yield Export(forwarded_name), AbsoluteVirtualAddress(va)
            yield Characteristic("forwarded export"), AbsoluteVirtualAddress(va)


def extract_file_import_names(vw, **kwargs) -> Iterator[Tuple[Feature, Address]]:
    """
    extract imported function names
    1. imports by ordinal:
     - modulename.#ordinal
    2. imports by name, results in two features to support importname-only matching:
     - modulename.importname
     - importname
    """
    for va, _, _, tinfo in vw.getImports():
        # vivisect source: tinfo = "%s.%s" % (libname, impname)
        modname, impname = tinfo.split(".", 1)
        if is_viv_ord_impname(impname):
            # replace ord prefix with #
            impname = "#" + impname[len("ord") :]

        addr = AbsoluteVirtualAddress(va)
        for name in capa.features.extractors.helpers.generate_symbols(modname, impname, include_dll=True):
            yield Import(name), addr


def is_viv_ord_impname(impname: str) -> bool:
    """
    return if import name matches vivisect's ordinal naming scheme `'ord%d' % ord`
    """
    if not impname.startswith("ord"):
        return False
    try:
        int(impname[len("ord") :])
    except ValueError:
        return False
    else:
        return True


def extract_file_section_names(vw, **kwargs) -> Iterator[Tuple[Feature, Address]]:
    for va, _, segname, _ in vw.getSegments():
        yield Section(segname), AbsoluteVirtualAddress(va)


def extract_file_strings(buf, **kwargs) -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.common.extract_file_strings(buf)


def extract_file_function_names(vw, **kwargs) -> Iterator[Tuple[Feature, Address]]:
    """
    extract the names of statically-linked library functions.
    """
    for va in sorted(vw.getFunctions()):
        addr = AbsoluteVirtualAddress(va)
        if viv_utils.flirt.is_library_function(vw, va):
            name = viv_utils.get_function_name(vw, va)
            yield FunctionName(name), addr
            if name.startswith("_"):
                # some linkers may prefix linked routines with a `_` to avoid name collisions.
                # extract features for both the mangled and un-mangled representations.
                # e.g. `_fwrite` -> `fwrite`
                # see: https://stackoverflow.com/a/2628384/87207
                yield FunctionName(name[1:]), addr


def extract_file_format(buf, **kwargs) -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.common.extract_format(buf)


def extract_features(vw, buf: bytes) -> Iterator[Tuple[Feature, Address]]:
    """
    extract file features from given workspace

    args:
      vw (vivisect.VivWorkspace): the vivisect workspace
      buf: the raw input file bytes

    yields:
      Tuple[Feature, Address]: a feature and its location.
    """

    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(vw=vw, buf=buf):  # type: ignore
            yield feature, addr


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    extract_file_function_names,
    extract_file_format,
)
