# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
import datetime

import idc
import idaapi
import idautils
import ida_bytes
import ida_loader

import capa
import capa.version
import capa.features.common

logger = logging.getLogger("capa")

# file type as returned by idainfo.file_type
SUPPORTED_FILE_TYPES = (
    idaapi.f_PE,
    idaapi.f_ELF,
    idaapi.f_BIN,
    # idaapi.f_MACHO,
)

# arch type as returned by idainfo.procname
SUPPORTED_ARCH_TYPES = ("metapc",)


def inform_user_ida_ui(message):
    idaapi.info("%s. Please refer to IDA Output window for more information." % message)


def is_supported_ida_version():
    version = float(idaapi.get_kernel_version())
    if version < 7.4 or version >= 8:
        warning_msg = "This plugin does not support your IDA Pro version"
        logger.warning(warning_msg)
        logger.warning("Your IDA Pro version is: %s. Supported versions are: IDA >= 7.4 and IDA < 8.0." % version)
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


def collect_metadata():
    """ """
    md5 = get_file_md5()
    sha256 = get_file_sha256()

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        # "argv" is not relevant here
        "sample": {
            "md5": md5,
            "sha1": "",  # not easily accessible
            "sha256": sha256,
            "path": idaapi.get_input_file_path(),
        },
        "analysis": {
            "format": idaapi.get_file_type_name(),
            "extractor": "ida",
            "base_address": idaapi.get_imagebase(),
            "layout": {
                # this is updated after capabilities have been collected.
                # will look like:
                #
                # "functions": { 0x401000: { "matched_basic_blocks": [ 0x401000, 0x401005, ... ] }, ... }
            },
        },
        "version": capa.version.__version__,
    }


class IDAIO:
    """
    An object that acts as a file-like object,
    using bytes from the current IDB workspace.
    """

    def __init__(self):
        super(IDAIO, self).__init__()
        self.offset = 0

    def seek(self, offset, whence=0):
        assert whence == 0
        self.offset = offset

    def read(self, size):
        ea = ida_loader.get_fileregion_ea(self.offset)
        if ea == idc.BADADDR:
            # best guess, such as if file is mapped at address 0x0.
            ea = self.offset

        logger.debug("reading 0x%x bytes at 0x%x (ea: 0x%x)", size, self.offset, ea)
        return ida_bytes.get_bytes(ea, size)

    def close(self):
        return
