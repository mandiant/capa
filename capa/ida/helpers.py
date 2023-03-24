# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import json
import logging
import datetime
import contextlib
from typing import Optional

import idc
import idaapi
import idautils
import ida_bytes
import ida_loader
from netnode import netnode

import capa
import capa.version
import capa.render.utils as rutils
import capa.features.common
import capa.render.result_document
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


def inform_user_ida_ui(message):
    idaapi.info(f"{message}. Please refer to IDA Output window for more information.")


def is_supported_ida_version():
    version = float(idaapi.get_kernel_version())
    if version < 7.4 or version >= 9:
        warning_msg = "This plugin does not support your IDA Pro version"
        logger.warning(warning_msg)
        logger.warning("Your IDA Pro version is: %s. Supported versions are: IDA >= 7.4 and IDA < 9.0." % version)
        return False
    return True


def is_supported_file_type():
    file_info = idaapi.get_inf_structure()
    if file_info.filetype not in SUPPORTED_FILE_TYPES:
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
    file_info = idaapi.get_inf_structure()
    if file_info.procname not in SUPPORTED_ARCH_TYPES or not any((file_info.is_32bit(), file_info.is_64bit())):
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


def collect_metadata(rules):
    """ """
    md5 = get_file_md5()
    sha256 = get_file_sha256()

    info: idaapi.idainfo = idaapi.get_inf_structure()
    if info.procname == "metapc" and info.is_64bit():
        arch = "x86_64"
    elif info.procname == "metapc" and info.is_32bit():
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

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "argv": [],
        "sample": {
            "md5": md5,
            "sha1": "",  # not easily accessible
            "sha256": sha256,
            "path": idaapi.get_input_file_path(),
        },
        "analysis": {
            "format": idaapi.get_file_type_name(),
            "arch": arch,
            "os": os,
            "extractor": "ida",
            "rules": rules,
            "base_address": idaapi.get_imagebase(),
            "layout": {
                # this is updated after capabilities have been collected.
                # will look like:
                #
                # "functions": { 0x401000: { "matched_basic_blocks": [ 0x401000, 0x401005, ... ] }, ... }
            },
            # ignore these for now - not used by IDA plugin.
            "feature_counts": {
                "file": {},
                "functions": {},
            },
            "library_functions": {},
        },
        "version": capa.version.__version__,
    }


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
        logger.error("%s", e, exc_info=True)
        return False


def load_and_verify_cached_results() -> Optional[capa.render.result_document.ResultDocument]:
    """verifies that cached results have valid (mapped) addresses for the current database"""
    logger.debug("loading cached capa results from netnode '%s'", CAPA_NETNODE)

    n = netnode.Netnode(CAPA_NETNODE)
    doc = capa.render.result_document.ResultDocument.parse_obj(json.loads(n[NETNODE_RESULTS]))

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
