import logging
import contextlib

import pefile
import speakeasy
import speakeasy.common as common
import speakeasy.windows.objman as objman
from speakeasy.profiler import Run

logger = logging.getLogger(__name__)
ASPACK = "aspack"


class NotPackedError(ValueError):
    def __init__(self):
        super(NotPackedError, self).__init__("not packed")


def detect_aspack(buf):
    """return True if the given buffer contains an ASPack'd PE file"""
    try:
        pe = pefile.PE(data=buf, fast_load=True)
    except:
        return False

    for section in pe.sections:
        try:
            section_name = section.Name.partition(b"\x00")[0].decode("ascii")
        except:
            continue

        if section_name in (".aspack", ".adata"):
            return True

    return False


def load_module2(se, module):
    """
    prepare an WindowsEmulator for emulation, without running it.

    this is useful when planning to manually control the emulator,
    such as via `Speakeasy.emu.emu_eng.start(...)`.

    much of this was derived from win32::Win32Emulator::run_module.
    """
    se._init_hooks()

    main_exe = None
    if not module.is_exe():
        container = se.emu.init_container_process()
        if container:
            se.emu.processes.append(container)
            se.emu.curr_process = container
    else:
        main_exe = module

    if main_exe:
        se.emu.user_modules = [main_exe] + se.emu.user_modules

    # Create an empty process object for the module if none is supplied
    if len(se.emu.processes) == 0:
        p = objman.Process(se.emu, path=module.get_emu_path(), base=module.base, pe=module)
        se.emu.curr_process = p

    t = objman.Thread(se.emu, stack_base=se.emu.stack_base, stack_commit=module.stack_commit)

    se.emu.om.objects.update({t.address: t})
    se.emu.curr_process.threads.append(t)
    se.emu.curr_thread = t

    peb = se.emu.alloc_peb(se.emu.curr_process)
    se.emu.init_teb(t, peb)


INSN_PUSHA = 0x60
INSN_POPA = 0x61


class AspackUnpacker(speakeasy.Speakeasy):
    def __init__(self, buf, debug=False):
        super(AspackUnpacker, self).__init__(debug=debug)
        self.buf = buf
        self.pe = pefile.PE(data=buf)
        self.module = self.load_module(data=buf)
        load_module2(self, self.module)

    def stepi(self):
        self.emu.emu_eng.start(self.emu.get_pc(), count=1)

    def remove_hook(self, hook_type, hook_handle):
        # TODO: this should be part of speakeasy
        self.emu.hooks[hook_type].remove(hook_handle)
        self.emu.emu_eng.hook_remove(hook_handle.handle)

    def remove_mem_read_hook(self, hook_handle):
        # TODO: this should be part of speakeasy
        self.remove_hook(common.HOOK_MEM_READ, hook_handle)

    @contextlib.contextmanager
    def mem_read_hook(self, hook):
        handle = self.add_mem_read_hook(hook)
        # if this fails, then there's still an unfixed bug in Speakeasy
        assert handle.handle != 0
        try:
            yield
        finally:
            self.remove_mem_read_hook(handle)

    def remove_code_hook(self, hook_handle):
        # TODO: this should be part of speakeasy
        self.remove_hook(common.HOOK_CODE, hook_handle)

    @contextlib.contextmanager
    def code_hook(self, hook):
        handle = self.add_code_hook(hook)
        assert handle.handle != 0
        try:
            yield
        finally:
            self.remove_code_hook(handle)

    def unpack(self):
        # prime the emulator
        # this is derived from winemu::WindowsEmulator::start()
        self.emu.curr_run = Run()
        self.emu.curr_mod = self.module
        self.emu.set_hooks()
        self.emu._set_emu_hooks()

        entrypoint = self.module.base + self.module.ep
        opcode = self.emu.mem_read(entrypoint, 1)[0]
        if opcode != INSN_PUSHA:
            raise ValueError("not packed with supported ASPack")

        # PUSHA
        self.emu.set_pc(entrypoint)
        self.stepi()

        def until_read(target):
            """return a mem_read hook that stops the emulator when an address is read."""

            def inner(emu, _access, addr, _size, _value, _ctx):
                if addr == target:
                    emu.stop()
                return True

            return inner

        # break on read of the saved context
        sp = self.emu.get_stack_ptr()
        with self.mem_read_hook(until_read(sp)):
            self.emu.emu_eng.start(self.emu.get_pc())

        # assert it is a POPA
        opcode = self.emu.mem_read(self.emu.get_pc(), 1)[0]
        if opcode != INSN_POPA:
            raise ValueError("not packed with supported ASPack")

        logger.debug("POPA: 0x%x", self.emu.get_pc())

        # now emulate to the next section hop
        aspack_section = self.module.get_section_by_name(".aspack")
        start = self.module.get_base() + aspack_section.VirtualAddress
        end = start + aspack_section.Misc_VirtualSize

        def until_section_hop(start, end):
            def inner(emu, addr, _size, _ctx):
                if addr < start or addr >= end:
                    emu.stop()
                return True

            return inner

        with self.code_hook(until_section_hop(start, end)):
            self.emu.emu_eng.start(self.emu.get_pc())

        oep = self.emu.get_pc()
        logger.debug("OEP: 0x%x", oep)

        mm = self.get_address_map(self.module.get_base())
        buf = self.mem_read(mm.get_base(), mm.get_size())

        pe = pefile.PE(data=buf)
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = oep - self.module.base
        return pe.write()


def unpack_aspack(buf):
    unpacker = AspackUnpacker(buf, debug=True)
    return unpacker.unpack()


UNPACKERS = {
    ASPACK: (detect_aspack, unpack_aspack),
}


def detect_packer(buf):
    for packer, (detect, _) in UNPACKERS.items():
        if detect(buf):
            return packer

    raise NotPackedError()


def is_packed(buf):
    try:
        detect_packer(buf)
        return True
    except NotPackedError:
        return False


def unpack_pe(packer, buf):
    (detect, unpack) = UNPACKERS[packer]
    return unpack(buf)
