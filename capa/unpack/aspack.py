import io
import struct
import logging
import contextlib
import collections

import pefile
import speakeasy
import speakeasy.common as se_common
import speakeasy.profiler
import speakeasy.windows.objman

logger = logging.getLogger(__name__)


def pefile_get_section_by_name(pe, section_name):
    for section in pe.sections:
        try:
            if section.Name.partition(b"\x00")[0].decode("ascii") == section_name:
                return section
        except:
            continue
    raise ValueError("section not found")


def prepare_emu_context(se, module):
    """
    prepare an Speakeasy instance for emulating the given module, without running it.

    this is useful when planning to manually control the emulator,
    such as via `Speakeasy.emu.emu_eng.start(...)`.
    typically, Speakeasy expects to do "Run based" analysis,
    which doesn't give us too much control.

    much of this was derived from win32::Win32Emulator::run_module.
    hopefully this can eventually be merged into Speakeasy.

    args:
      se (speakeasy.Speakeasy): the instance to prepare
      module (speakeasy.Module): the module that will be emulated
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
        p = speakeasy.windows.objman.Process(se.emu, path=module.get_emu_path(), base=module.base, pe=module)
        se.emu.curr_process = p

    t = speakeasy.windows.objman.Thread(se.emu, stack_base=se.emu.stack_base, stack_commit=module.stack_commit)

    se.emu.om.objects.update({t.address: t})
    se.emu.curr_process.threads.append(t)
    se.emu.curr_thread = t

    peb = se.emu.alloc_peb(se.emu.curr_process)
    se.emu.init_teb(t, peb)


INSN_PUSHA = 0x60
INSN_POPA = 0x61


class AspackUnpacker(speakeasy.Speakeasy):
    name = "aspack"

    def __init__(self, buf, debug=False):
        super(AspackUnpacker, self).__init__(debug=debug)
        self.module = self.load_module(data=buf)
        prepare_emu_context(self, self.module)

    @staticmethod
    def detect_aspack(buf):
        """
        return True if the given buffer contains an ASPack'd PE file.
        we detect aspack by looking at the section names for .aspack.
        the unpacking routine contains further validation and will raise an exception if necessary.

        args:
          buf (bytes): the contents of a PE file.

        returns: bool
        """
        try:
            pe = pefile.PE(data=buf, fast_load=True)
        except:
            return False

        try:
            pefile_get_section_by_name(pe, ".aspack")
        except ValueError:
            pass
        else:
            return True

        return False

    @classmethod
    def unpack_pe(cls, buf):
        """
        unpack the given buffer that contains an ASPack'd PE file.
        return the contents of a reconstructed PE file.

        args:
          buf (bytes): the contents of an ASPack'd PE file.

        returns: bytes
        """
        unpacker = cls(buf)
        return unpacker.unpack()

    def stepi(self):
        self.emu.emu_eng.start(self.emu.get_pc(), count=1)

    def remove_hook(self, hook_type, hook_handle):
        # TODO: this should be part of speakeasy
        self.emu.hooks[hook_type].remove(hook_handle)
        self.emu.emu_eng.hook_remove(hook_handle.handle)

    def remove_mem_read_hook(self, hook_handle):
        # TODO: this should be part of speakeasy
        self.remove_hook(se_common.HOOK_MEM_READ, hook_handle)

    @contextlib.contextmanager
    def mem_read_hook(self, hook):
        """
        context manager for temporarily installing a hook on the emulator.

        example:

            with self.mem_read_hook(lambda emu, access, addr, size, ctx: emu.stop()):
                self.emu.emu_eng.start(0x401000)

        args:
          hook (speakeasy.common.MemReadHook): the hook to install
        """
        handle = self.add_mem_read_hook(hook)
        # if this fails, then there's still an unfixed bug in Speakeasy
        assert handle.handle != 0
        try:
            yield
        finally:
            self.remove_mem_read_hook(handle)

    def remove_code_hook(self, hook_handle):
        # TODO: this should be part of speakeasy
        self.remove_hook(se_common.HOOK_CODE, hook_handle)

    @contextlib.contextmanager
    def code_hook(self, hook):
        """
        context manager for temporarily installing a hook on the emulator.

        example:

            with self.code_hook(lambda emu, addr, size, ctx: emu.stop()):
                self.emu.emu_eng.start(0x401000)

        args:
          hook (speakeasy.common.CodeHook): the hook to install
        """
        handle = self.add_code_hook(hook)
        assert handle.handle != 0
        try:
            yield
        finally:
            self.remove_code_hook(handle)

    def read_ptr(self, va):
        endian = "little"
        val = self.mem_read(va, self.emu.ptr_size)
        return int.from_bytes(val, endian)

    def dump(self):
        """
        emulate the loaded module, pausing after an appropriate section hop.
        then, dump and return the module's memory and OEP.

        this routine is specific to aspack. it makes the following assumptions:
          - aspack starts with a PUSHA to save off the CPU context
          - aspeck then runs its unpacking stub
          - aspeck executes POPA to restore the CPU context
          - aspack section hops to the OEP

        we'll emulate in a few phases:
          1. single step over PUSHA at the entrypoint
          2. extract the address of the saved CPU context
          3. emulate until the saved CPU context is read
          4. assert this is a POPA instruction
          5. emulate until a section hop
          6. profit!

        return the module's memory segment and the OEP.

        returns: Tuple[byte, int]
        """

        # prime the emulator.
        # this is derived from winemu::WindowsEmulator::start()
        self.emu.curr_run = speakeasy.profiler.Run()
        self.emu.curr_mod = self.module
        self.emu.set_hooks()
        self.emu._set_emu_hooks()

        # 0. sanity checking: assert entrypoint is a PUSHA instruction
        entrypoint = self.module.base + self.module.ep
        opcode = self.emu.mem_read(entrypoint, 1)[0]
        if opcode != INSN_PUSHA:
            raise ValueError("not packed with supported ASPack")

        # 1. single step over PUSHA
        self.emu.set_pc(entrypoint)
        self.stepi()

        # 2. extract address of saved CPU context
        saved_cpu_context = self.emu.get_stack_ptr()

        # 3. emulate until saved CPU context is accessed
        def until_read(target):
            """return a mem_read hook that stops the emulator when an address is read."""

            def inner(emu, _access, addr, _size, _value, _ctx):
                if addr == target:
                    emu.stop()
                return True

            return inner

        with self.mem_read_hook(until_read(saved_cpu_context)):
            self.emu.emu_eng.start(self.emu.get_pc())

        # 4. assert this is a POPA instruction
        opcode = self.emu.mem_read(self.emu.get_pc(), 1)[0]
        if opcode != INSN_POPA:
            raise ValueError("not packed with supported ASPack")
        logger.debug("POPA: 0x%x", self.emu.get_pc())

        # 5. emulate until a section hop
        aspack_section = self.module.get_section_by_name(".aspack")
        start = self.module.base + aspack_section.VirtualAddress
        end = start + aspack_section.Misc_VirtualSize

        def until_section_hop(start, end):
            def inner(emu, addr, _size, _ctx):
                if addr < start or addr >= end:
                    emu.stop()
                return True

            return inner

        with self.code_hook(until_section_hop(start, end)):
            self.emu.emu_eng.start(self.emu.get_pc())

        # 6. dump and return
        oep = self.emu.get_pc()
        logger.debug("OEP: 0x%x", oep)

        mm = self.get_address_map(self.module.base)
        buf = self.mem_read(mm.base, mm.size)

        return buf, oep

    def fixup(self, buf, oep):
        """
        fixup a PE image that's been dumped from memory after unpacking aspack.

        there are two big fixes that need to happen:
          1. update the section pointers and sizes
          2. rebuild the import table

        for (1) updating the section pointers, we'll just update the
        physical pointers to match the virtual pointers, since this is a loaded image.

        for (2) rebuilding the import table, we'll:
          (a) inspect the emulation results for resolved imports, which tells us dll/symbol names
          (b) scan the dumped image for the unpacked import thunks (Import Address Table/Thunk Table)
          (c) match the import thunks with resolved imports
          (d) build the import table structures
          (e) write the reconstructed table into the .aspack section

        since the .aspack section contains the unpacking stub, which is no longer used,
        then we'll write the reconstructed IAT there. hopefully its big enough.
        """
        pe = pefile.PE(data=buf)

        pe.OPTIONAL_HEADER.AddressOfEntryPoint = oep - self.module.base

        # 1. update section pointers and sizes.
        for section in pe.sections:
            section.PointerToRawData = section.VirtualAddress
            section.SizeOfRawData = section.Misc_VirtualSize

        # 2. rebuild the import table

        # place the reconstructed import table in the .aspack section (unpacking stub)
        reconstruction_target = pefile_get_section_by_name(pe, ".aspack").VirtualAddress

        # mapping from import pointer to (dll name, symbol name).
        # the import pointer is generated by speakeasy and is not mapped.
        # it often looks something like 0xfeedf008.
        # as we encounter pointers with values like this, we can resolve the symbol.
        imports = {}

        # 2a. find resolved imports
        for addr, (dll, sym) in self.module.import_table.items():
            # these are items in the original import table.
            logger.debug(f"found static import  {dll}.{sym}")
            imports[addr] = (dll, sym)
        for (addr, dll, sym) in self.emu.dyn_imps:
            # these are imports that have been resolved at runtime by the unpacking stub.
            logger.debug(f"found dynamic import {dll}.{sym}")
            imports[addr] = (dll, sym)

        # 2b. find the existing thunk tables
        # these are pointer-aligned tables of import pointers.
        # in my test sample, its found at the start of the first section.

        # ordered list of tuples (VA, import pointer)
        # look up the symbol using the import pointer and the `imports` mapping.
        thunks = []

        # scan from the start of the first section
        # until we reach values that don't look like thunk tables.
        for va in range(pe.sections[0].VirtualAddress + self.module.base, 0xFFFFFFFFFFFFFFFF, self.emu.ptr_size):
            ptr = self.read_ptr(va)
            if ptr == 0:
                # probably padding/terminating entry
                continue

            if ptr in imports:
                thunks.append((va, ptr,))
                logger.debug(f"found import thunk at {va:08x} to {ptr:08x} for {imports[ptr][0]}\t{imports[ptr][1]}")
                continue

            # otherwise, at the end of the thunk tables
            break

        # collect the thunk entries into contiguous tables, grouped by dll name.
        #
        # list of thunk tuples that are contiguous and have the same dll name:
        #   (VA, import pointer, dll name, symbol name)
        curr_idt_table = []
        # list of list of thunk tuples, like above
        idt_tables = []
        for thunk in thunks:
            va, imp = thunk
            dll, sym = imports[imp]

            if not curr_idt_table:
                curr_idt_table.append((va, imp, dll, sym))
            elif curr_idt_table[0][2] == dll:
                curr_idt_table.append((va, imp, dll, sym))
            else:
                idt_tables.append(curr_idt_table)
                curr_idt_table = [(va, imp, dll, sym)]
        idt_tables.append(curr_idt_table)

        # 2d. build the import table structures

        # mapping from the data identifier to its RVA (which will be found within the reconstruction blob)
        locations = {}
        # the raw bytes of the reconstructed import structures.
        # it will have the following layout:
        #   1. DLL name strings and Hint/Name table entries
        #   2. Import Lookup Tables (points into (1))
        #   3. Import Directory Tables (points into (1), (2), and original Thunk Tables)
        reconstruction = io.BytesIO()

        # list of dll names
        dlls = list(sorted(set(map(lambda pair: pair[0], imports.values()))))
        # mapping from dll name to list of symbols
        symbols = collections.defaultdict(set)
        for dll, sym in imports.values():
            symbols[dll].add(sym)

        # emit strings into the reconstruction blob
        for dll in dlls:
            locations[("dll", dll)] = reconstruction_target + reconstruction.tell()
            reconstruction.write(dll.encode("ascii") + b"\x00")
            if reconstruction.tell() % 2 == 1:
                # padding
                reconstruction.write(b"\x00")

            for sym in sorted(symbols[dll]):
                locations[("hint", dll, sym)] = reconstruction_target + reconstruction.tell()
                # export name pointer table hint == 0
                reconstruction.write(b"\x00\x00")
                # name
                reconstruction.write(sym.encode("ascii") + b"\x00")
                if reconstruction.tell() % 2 == 1:
                    # padding
                    reconstruction.write(b"\x00")

        # emit Import Lookup Tables for each recovered thunk table
        ptr_format = "<I" if self.emu.ptr_size == 4 else "<Q"
        for i, idt_entry in enumerate(idt_tables):
            locations[("import lookup table", i)] = reconstruction_target + reconstruction.tell()
            for (va, imp, dll, sym) in idt_entry:
                reconstruction.write(struct.pack(ptr_format, locations[("hint", dll, sym)]))
            reconstruction.write(b"\x00" * 8)

        # emit Import Descriptor Tables for each recovered thunk table
        IDT_ENTRY_SIZE = 0x20
        for i, idt_entry in enumerate(idt_tables):
            va, _, dll, _ = idt_entry[0]
            rva = va - self.module.base
            locations[("import descriptor table", i)] = reconstruction_target + reconstruction.tell()

            # import lookup table rva
            reconstruction.write(struct.pack("<I", locations[("import lookup table", i)]))
            # date stamp
            reconstruction.write(struct.pack("<I", 0x0))
            # forwarder chain
            reconstruction.write(struct.pack("<I", 0x0))
            # name rva
            reconstruction.write(struct.pack("<I", locations[("dll", dll)]))
            # import address table rva
            reconstruction.write(struct.pack("<I", rva))
        # empty last entry
        reconstruction.write(b"\x00" * IDT_ENTRY_SIZE)

        # if the reconstructed import structures are larger than the unpacking stub...
        # i'm not sure what we'll do. probably need to add a section.
        assert len(reconstruction.getvalue()) <= pefile_get_section_by_name(pe, ".aspack").Misc_VirtualSize

        pe.set_bytes_at_rva(reconstruction_target, reconstruction.getvalue())
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = locations[("import descriptor table", 0)]
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = IDT_ENTRY_SIZE * len(idt_tables)

        return pe.write()

    def unpack(self):
        buf, oep = self.dump()
        buf = self.fixup(buf, oep)
        return buf


if __name__ == "__main__":
    import sys

    input = sys.argv[1]
    output = sys.argv[1]

    with open(sys.argv[1], "rb") as f:
        buf = f.read()

    with open(sys.argv[2], "wb") as f:
        f.write(AspackUnpacker.unpack_pe(buf))
