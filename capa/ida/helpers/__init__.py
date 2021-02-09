# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
import datetime

import idc
import six
import idaapi
import idautils

import capa

logger = logging.getLogger("capa")

SUPPORTED_IDA_VERSIONS = [
    "7.1",
    "7.2",
    "7.3",
    "7.4",
    "7.5",
]

# file type names as returned by idaapi.get_file_type_name()
SUPPORTED_FILE_TYPES = [
    "Portable executable for 80386 (PE)",
    "Portable executable for AMD64 (PE)",
    "Binary file",  # x86/AMD64 shellcode support
]


def inform_user_ida_ui(message):
    idaapi.info("%s. Please refer to IDA Output window for more information." % message)


def is_supported_ida_version():
    version = idaapi.get_kernel_version()
    if version not in SUPPORTED_IDA_VERSIONS:
        warning_msg = "This plugin does not support your IDA Pro version"
        logger.warning(warning_msg)
        logger.warning(
            "Your IDA Pro version is: %s. Supported versions are: %s." % (version, ", ".join(SUPPORTED_IDA_VERSIONS))
        )
        return False
    return True


def is_supported_file_type():
    file_type = idaapi.get_file_type_name()
    if file_type not in SUPPORTED_FILE_TYPES:
        logger.error("-" * 80)
        logger.error(" Input file does not appear to be a PE file.")
        logger.error(" ")
        logger.error(
            " capa currently only supports analyzing PE files (or binary files containing x86/AMD64 shellcode) with IDA."
        )
        logger.error(" If you don't know the input file type, you can try using the `file` utility to guess it.")
        logger.error("-" * 80)
        return False
    return True


def get_disasm_line(va):
    """ """
    return idc.generate_disasm_line(va, idc.GENDSM_FORCE_CODE)


def is_func_start(ea):
    """ check if function stat exists at virtual address """
    f = idaapi.get_func(ea)
    return f and f.start_ea == ea


def get_func_start_ea(ea):
    """ """
    f = idaapi.get_func(ea)
    return f if f is None else f.start_ea


def get_file_md5():
    """ """
    md5 = idautils.GetInputFileMD5()
    if not isinstance(md5, six.string_types):
        md5 = capa.features.bytes_to_str(md5)
    return md5


def get_file_sha256():
    """ """
    sha256 = idaapi.retrieve_input_file_sha256()
    if not isinstance(sha256, six.string_types):
        sha256 = capa.features.bytes_to_str(sha256)
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
        },
        "version": capa.version.__version__,
    }
