# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging
import datetime

import idc
import idaapi
import idautils

import capa

logger = logging.getLogger("capa")

# file type names as returned by idaapi.get_file_type_name()
SUPPORTED_FILE_TYPES = [
    "Portable executable for 80386 (PE)",
    "Portable executable for AMD64 (PE)",
    "Binary file",  # x86/AMD64 shellcode support
]


def inform_user_ida_ui(message):
    idaapi.info("%s. Please refer to IDA Output window for more information." % message)


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
        inform_user_ida_ui("capa does not support the format of this file")
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


def collect_metadata():
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        # "argv" is not relevant here
        "sample": {
            "md5": capa.features.bytes_to_str(idautils.GetInputFileMD5()),
            # "sha1" not easily accessible
            "sha256": capa.features.bytes_to_str(idaapi.retrieve_input_file_sha256()),
            "path": idaapi.get_input_file_path(),
        },
        "analysis": {"format": idaapi.get_file_type_name(), "extractor": "ida",},
        "version": capa.version.__version__,
    }
