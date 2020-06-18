import idaapi
import idc


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
