import logging

import idaapi
import idc

logger = logging.getLogger()

# file type names as returned by idaapi.get_file_type_name()
SUPPORTED_FILE_TYPES = [
    'Portable executable for 80386 (PE)',
    'Portable executable for AMD64 (PE)',
    'Binary file'  # x86/AMD64 shellcode support
]


def inform_user_ida_ui(message):
    idaapi.info('%s. Please refer to IDA Output window for more information.' % message)


def is_supported_file_type():
    file_type = idaapi.get_file_type_name()

    if file_type not in SUPPORTED_FILE_TYPES:
        logger.error('-' * 80)
        logger.error(' Input file does not appear to be a PE file.')
        logger.error(' ')
        logger.error(' capa currently only supports analyzing PE files (or x86/AMD64 shellcode).')
        logger.error(' If you don\'t know the input file type, you can try using the `file` utility to guess it.')
        logger.error('-' * 80)

        inform_user_ida_ui('capa does not support the format of this file')

        return False

    # support binary files specifically for x86/AMD64 shellcode
    # warn user binary file is loaded but still allow capa to process it
    # TODO: check specific architecture of binary files based on how user configured IDA processors
    if file_type == 'Binary file':
        logger.warning('-' * 80)
        logger.warning(' Input file appears to be a binary file.')
        logger.warning(' ')
        logger.warning(' capa currently only supports analyzing binary files containing x86/AMD64 shellcode.')
        logger.warning(' This means the results may be misleading or incomplete if the binary file is not x86/AMD64.')
        logger.warning(' If you don\'t know the input file type, you can try using the `file` utility to guess it.')
        logger.warning('-' * 80)

        inform_user_ida_ui('capa encountered warnings during analysis')

    return True


def get_disasm_line(va):
    ''' '''
    return idc.generate_disasm_line(va, idc.GENDSM_FORCE_CODE)


def is_func_start(ea):
    ''' check if function stat exists at virtual address '''
    f = idaapi.get_func(ea)
    return f and f.start_ea == ea


def get_func_start_ea(ea):
    ''' '''
    f = idaapi.get_func(ea)
    return f if f is None else f.start_ea
