# Copyright 2021 Google LLC
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

import logging
import datetime
import contextlib
from typing import Optional
from pathlib import Path

import idc
import idaapi
import ida_ida
import ida_nalt
import idautils
import ida_bytes
import ida_loader
from netnode import netnode

import capa
import capa.version
import capa.render.utils as rutils
import capa.features.common
import capa.features.freeze
import capa.render.result_document as rdoc
from capa.features.address import AbsoluteVirtualAddress

logger = logging.getLogger("capa")

# file type as returned by idainfo.file_type
SUPPORTED_FILE_TYPES = (
    idaapi.f_PE,
    idaapi.f_ELF,
    idaapi.f_BIN,
    idaapi.f_COFF,
    # idaapi.f_MACHO,
)

# arch type as returned by idainfo.procname
SUPPORTED_ARCH_TYPES = ("metapc",)

CAPA_NETNODE = f"$ com.mandiant.capa.v{capa.version.__version__}"
NETNODE_RESULTS = "results"
NETNODE_RULES_CACHE_ID = "rules-cache-id"


# wrappers for IDA Pro (IDAPython) 7, 8 and 9 compability
version = float(idaapi.get_kernel_version())
if version < 9.0:

    def get_filetype() -> "ida_ida.filetype_t":
        return idaapi.get_inf_structure().filetype

    def get_processor_name() -> str:
        return idaapi.get_inf_structure().procname

    def is_32bit() -> bool:
        info: idaapi.idainfo = idaapi.get_inf_structure()
        return info.is_32bit()

    def is_64bit() -> bool:
        info: idaapi.idainfo = idaapi.get_inf_structure()
        return info.is_64bit()

    def retrieve_input_file_md5() -> str:
        return ida_nalt.retrieve_input_file_md5()

    def retrieve_input_file_sha256() -> str:
        return ida_nalt.retrieve_input_file_sha256()

else:

    def get_filetype() -> "ida_ida.filetype_t":
        return ida_ida.inf_get_filetype()

    def get_processor_name() -> str:
        return idc.get_processor_name()

    def is_32bit() -> bool:
        return idaapi.inf_is_32bit_exactly()

    def is_64bit() -> bool:
        return idaapi.inf_is_64bit()

    def retrieve_input_file_md5() -> str:
        return ida_nalt.retrieve_input_file_md5().hex()

    def retrieve_input_file_sha256() -> str:
        return ida_nalt.retrieve_input_file_sha256().hex()


def inform_user_ida_ui(message):
    # this isn't a logger, this is IDA's logging facility
    idaapi.info(f"{message}. Please refer to IDA Output window for more information.")  # noqa: G004


def is_supported_ida_version():
    version = float(idaapi.get_kernel_version())
    if version < 7.4 or version >= 10:
        warning_msg = "This plugin does not support your IDA Pro version"
        logger.warning(warning_msg)
        logger.warning("Your IDA Pro version is: %s. Supported versions are: IDA >= 7.4 and IDA < 10.0.", version)
        return False
    return True


def is_supported_file_type():
    if get_filetype() not in SUPPORTED_FILE_TYPES:
        logger.error("-" * 80)
        logger.error(" Input file does not appear to be a supported file type.")
        logger.error(" ")
        logger.error(
            " capa currently only supports analyzing PE, ELF, or binary files containing x86 (32- and 64-bit) shellcode."
        )
        logger.error(" If you don't know the input file type, you can try using the `file` utility to guess it.")
        logger.error("-" * 80)
        return False
    return True


def is_supported_arch_type():
    if get_processor_name() not in SUPPORTED_ARCH_TYPES or not any((is_32bit(), is_64bit())):
        logger.error("-" * 80)
        logger.error(" Input file does not appear to target a supported architecture.")
        logger.error(" ")
        logger.error(" capa currently only supports analyzing x86 (32- and 64-bit).")
        logger.error("-" * 80)
        return False
    return True


def get_disasm_line(va):
    """ """
    return idc.generate_disasm_line(va, idc.GENDSM_FORCE_CODE)


def is_func_start(ea):
    """check if function stat exists at virtual address"""
    f = idaapi.get_func(ea)
    return f and f.start_ea == ea


def get_func_start_ea(ea):
    """ """
    f = idaapi.get_func(ea)
    return f if f is None else f.start_ea


def get_file_md5():
    """ """
    md5 = idautils.GetInputFileMD5()
    if not isinstance(md5, str):
        md5 = capa.features.common.bytes_to_str(md5)
    return md5


def get_file_sha256():
    """ """
    sha256 = idaapi.retrieve_input_file_sha256()
    if not isinstance(sha256, str):
        sha256 = capa.features.common.bytes_to_str(sha256)
    return sha256


def collect_metadata(rules: list[Path]):
    """ """
    md5 = get_file_md5()
    sha256 = get_file_sha256()

    procname = get_processor_name()
    if procname == "metapc" and is_64bit():
        arch = "x86_64"
    elif procname == "metapc" and is_32bit():
        arch = "x86"
    else:
        arch = "unknown arch"

    format_name: str = ida_loader.get_file_type_name()
    if "PE" in format_name:
        os = "windows"
    elif "ELF" in format_name:
        with contextlib.closing(capa.ida.helpers.IDAIO()) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)
    else:
        os = "unknown os"

    return rdoc.Metadata(
        timestamp=datetime.datetime.now(),
        version=capa.version.__version__,
        argv=(),
        sample=rdoc.Sample(
            md5=md5,
            sha1="",  # not easily accessible
            sha256=sha256,
            path=idaapi.get_input_file_path(),
        ),
        flavor=rdoc.Flavor.STATIC,
        analysis=rdoc.StaticAnalysis(
            format=idaapi.get_file_type_name(),
            arch=arch,
            os=os,
            extractor="ida",
            rules=tuple(r.resolve().absolute().as_posix() for r in rules),
            base_address=capa.features.freeze.Address.from_capa(AbsoluteVirtualAddress(idaapi.get_imagebase())),
            layout=rdoc.StaticLayout(
                functions=(),
                # this is updated after capabilities have been collected.
                # will look like:
                #
                # "functions": { 0x401000: { "matched_basic_blocks": [ 0x401000, 0x401005, ... ] }, ... }
            ),
            # ignore these for now - not used by IDA plugin.
            feature_counts=rdoc.StaticFeatureCounts(file=0, functions=()),
            library_functions=(),
        ),
    )


class IDAIO:
    """
    An object that acts as a file-like object,
    using bytes from the current IDB workspace.
    """

    def __init__(self):
        super().__init__()
        self.offset = 0

    def seek(self, offset, whence=0):
        assert whence == 0
        self.offset = offset

    def read(self, size):
        ea = ida_loader.get_fileregion_ea(self.offset)
        if ea == idc.BADADDR:
            logger.debug("cannot read 0x%x bytes at 0x%x (ea: BADADDR)", size, self.offset)
            return b""

        logger.debug("reading 0x%x bytes at 0x%x (ea: 0x%x)", size, self.offset, ea)

        # get_bytes returns None on error, for consistency with read always return bytes
        return ida_bytes.get_bytes(ea, size) or b""

    def close(self):
        return


def save_cached_results(resdoc):
    logger.debug("saving cached capa results to netnode '%s'", CAPA_NETNODE)
    n = netnode.Netnode(CAPA_NETNODE)
    n[NETNODE_RESULTS] = resdoc.json()


def idb_contains_cached_results() -> bool:
    try:
        n = netnode.Netnode(CAPA_NETNODE)
        return bool(n.get(NETNODE_RESULTS))
    except netnode.NetnodeCorruptError as e:
        logger.exception(str(e))
        return False


def load_and_verify_cached_results() -> Optional[rdoc.ResultDocument]:
    """verifies that cached results have valid (mapped) addresses for the current database"""
    logger.debug("loading cached capa results from netnode '%s'", CAPA_NETNODE)

    n = netnode.Netnode(CAPA_NETNODE)
    doc = rdoc.ResultDocument.model_validate_json(n[NETNODE_RESULTS])

    for rule in rutils.capability_rules(doc):
        for location_, _ in rule.matches:
            location = location_.to_capa()
            if isinstance(location, AbsoluteVirtualAddress):
                ea = int(location)
                if not idaapi.is_mapped(ea):
                    logger.error("cached address %s is not a valid location in this database", hex(ea))
                    return None
    return doc


def save_rules_cache_id(ruleset_id):
    logger.debug("saving ruleset ID to netnode '%s'", CAPA_NETNODE)
    n = netnode.Netnode(CAPA_NETNODE)
    n[NETNODE_RULES_CACHE_ID] = ruleset_id


def load_rules_cache_id():
    n = netnode.Netnode(CAPA_NETNODE)
    return n[NETNODE_RULES_CACHE_ID]


def delete_cached_results():
    logger.debug("deleting cached capa data")
    n = netnode.Netnode(CAPA_NETNODE)
    del n[NETNODE_RESULTS]
