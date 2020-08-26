import io
import struct
import logging
import contextlib
import collections

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

    def dump(self):
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
        return buf, oep

    def fixup(self, buf, oep):
        # it seems the .adata section (last section) may not be present.
        # we need this to be around because we're going to place the import table here.
        # so pad this out with NULL bytes.
        pe = pefile.PE(data=buf, fast_load=True)
        last_section = pe.sections[-1]
        expected_size = last_section.VirtualAddress + last_section.Misc_VirtualSize
        if len(buf) < expected_size:
            buf += b"\x00" * (expected_size - len(buf))

        pe = pefile.PE(data=buf)
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = oep - self.module.base

        # since we're just pulling a big chunk from memory,
        # update the sections to point to their virtual layout.
        for section in pe.sections:
            section.PointerToRawData = section.VirtualAddress
            section.SizeOfRawData = section.Misc_VirtualSize

        # mapping from virtual address to (dll name, symbol name).
        # the virtual address is generated by speakeasy and is not mapped.
        # it often looks something like 0xfeedf008.
        # as we encounter pointers with values like this, we can resolve the symbol.
        imports = {}
        for addr, (dll, sym) in self.module.import_table.items():
            # these are items in the original import table.
            logger.debug(f"found static import  {dll}.{sym}")
            imports[addr] = (dll, sym)

        for (addr, dll, sym) in self.emu.dyn_imps:
            # these are imports that have been resolved at runtime by the unpacking stub.
            logger.debug(f"found dynamic import {dll}.{sym}")
            imports[addr] = (dll, sym)

        # find the existing thunk tables
        # these are pointer-aligned tables of import pointers

        # ordered list of tuples (VA, import pointer)
        # look up the symbol using the import pointer and the `imports` mapping.
        thunks = []

        # aspack puts the import table at the start of the first section?
        # or maybe its just the sample i'm looking at.
        for va in range(pe.sections[0].VirtualAddress + self.module.base, 0xFFFFFFFFFFFFFFFF, self.emu.get_ptr_size()):
            ptr = self.read_ptr(va)
            if ptr == 0:
                continue

            if ptr in imports:
                thunks.append((va, ptr,))
                logger.debug(f"found import thunk at {va:08x} to {ptr:08x} for {imports[ptr][0]}\t{imports[ptr][1]}")
                continue

            break

        # list of dll names
        dlls = list(sorted(set(map(lambda pair: pair[0], imports.values()))))
        # mapping from dll name to list of symbols
        symbols = collections.defaultdict(set)
        for dll, sym in imports.values():
            symbols[dll].add(sym)
        for dll, syms in list(symbols.items()):
            symbols[dll] = list(sorted(syms))

        adata_rva = 0x0
        for section in pe.sections:
            try:
                section_name = section.Name.partition(b"\x00")[0].decode("ascii")
            except:
                continue

            if section_name == ".adata":
                adata_rva = section.VirtualAddress
                break
        assert adata_rva != 0x0
        # assume .adata is big enough
        reconstruction_target = adata_rva

        # mapping from the data identifier to its RVA (and found within the reconstruction blob)
        locations = {}
        reconstruction = io.BytesIO()

        # emit strings into the reconstruction blob
        for dll in dlls:
            locations[("dll", dll)] = reconstruction_target + reconstruction.tell()
            reconstruction.write(dll.encode("ascii") + b"\x00")

            for sym in symbols[dll]:
                locations[("hint", dll, sym)] = reconstruction_target + reconstruction.tell()
                # hint == 0
                reconstruction.write(b"\x00\x00")
                # name
                reconstruction.write(sym.encode("ascii") + b"\x00")
                if reconstruction.tell() % 2 == 1:
                    # padding
                    reconstruction.write(b"\x00")

        # list of thunk tuples from thunks that are contiguous and have the same dll name.
        # (VA, import pointer, dll name, symbol name)
        curr_idt_entry = []
        # list of list of thunk tuples, like above
        idt_entries = []
        for thunk in thunks:
            va, imp = thunk
            dll, sym = imports[imp]

            if not curr_idt_entry:
                curr_idt_entry.append((va, imp, dll, sym))
            elif curr_idt_entry[0][2] == dll:
                curr_idt_entry.append((va, imp, dll, sym))
            else:
                idt_entries.append(curr_idt_entry)
                curr_idt_entry = [(va, imp, dll, sym)]
        idt_entries.append(curr_idt_entry)

        # emit name tables for each IDT/dll
        ptr_format = "<I" if self.emu.get_ptr_size() == 4 else "<Q"
        for i, idt_entry in enumerate(idt_entries):
            print(idt_entry[0][2], len(idt_entry))

            locations[("import lookup table", i)] = reconstruction_target + reconstruction.tell()
            for (va, imp, dll, sym) in idt_entry:
                reconstruction.write(struct.pack(ptr_format, locations[("hint", dll, sym)]))
            reconstruction.write(b"\x00" * 8)

        # emit IDTs
        for i, idt_entry in enumerate(idt_entries):
            va, _, dll, _ = idt_entry[0]
            rva = va - self.module.get_base()
            locations[("idt", i)] = reconstruction_target + reconstruction.tell()

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

        reconstruction.write(b"\x00\x00\x00\x00" * 5)

        IDT_ENTRY_SIZE = 0x20

        # TODO assert size is ok
        # and/or extend .adata

        pe.set_bytes_at_rva(reconstruction_target, reconstruction.getvalue())
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = locations[("idt", 0)]
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = IDT_ENTRY_SIZE * len(idt_entries)

        return pe.write()

    def read_ptr(self, va):
        endian = "little"
        val = self.mem_read(va, self.emu.get_ptr_size())
        return int.from_bytes(val, endian)

    def unpack(self):
        buf, oep = self.dump()
        buf = self.fixup(buf, oep)
        return buf


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
