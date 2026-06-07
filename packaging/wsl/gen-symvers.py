#!/usr/bin/env python3
"""Reconstruct a kernel Module.symvers from a stripped vmlinux.

The official WSL kernel image (Microsoft.WSL.Kernel nuget) ships no
Module.symvers and no headers tree with one, so modpost cannot resolve
exported-symbol CRCs when building an out-of-tree module against it.

The CRCs are still recoverable: even after `.symtab` is stripped, the
allocated __ksymtab/__kcrctab sections survive in vmlinux. This walks them
and emits a Module.symvers that modpost reads as `$(KSRC)/Module.symvers`.

Valid only for:
  - CONFIG_MODVERSIONS=y           (CRCs exist at all)
  - CONFIG_MODULE_REL_CRCS unset   (__kcrctab holds raw u32 CRCs)
  - PREL32 ksymtab layout          (x86-64 / arm64 modern kernels)

  struct kernel_symbol { s32 value_offset; s32 name_offset; s32 namespace_offset; }
  the referenced pointer is `&field + *field` (offset_to_ptr / PREL32).

Usage: gen-symvers.py <vmlinux> > Module.symvers
"""
import struct
import sys


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen-symvers.py <vmlinux> > Module.symvers")
    elf = open(sys.argv[1], "rb").read()

    if elf[:4] != b"\x7fELF" or elf[4] != 2:
        sys.exit("not an ELF64 file")

    # --- ELF64 section header table ---
    e_shoff = struct.unpack_from("<Q", elf, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", elf, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", elf, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]

    headers = []
    for i in range(e_shnum):
        name, _type, _flags, addr, off, size = struct.unpack_from(
            "<IIQQQQ", elf, e_shoff + i * e_shentsize)
        headers.append((name, addr, off, size))

    _, _, shstr_off, shstr_size = headers[e_shstrndx]
    shstr = elf[shstr_off:shstr_off + shstr_size]

    sections = {}  # name -> (addr, off, size)
    for name_off, addr, off, size in headers:
        name = shstr[name_off:shstr.index(b"\0", name_off)].decode()
        sections[name] = (addr, off, size)

    kstr_addr, kstr_off, kstr_size = sections["__ksymtab_strings"]
    kstr = elf[kstr_off:kstr_off + kstr_size]

    def string_at(addr):
        """Resolve a PREL32 target into __ksymtab_strings; None if outside it."""
        pos = addr - kstr_addr
        if pos < 0 or pos >= len(kstr):
            return None
        return kstr[pos:kstr.index(b"\0", pos)].decode()

    def emit(sym_name, crc_name, export):
        if sym_name not in sections:
            return 0
        sym_addr, sym_off, sym_size = sections[sym_name]
        crc_addr, crc_off, crc_size = sections[crc_name]
        symdata = elf[sym_off:sym_off + sym_size]
        crcdata = elf[crc_off:crc_off + crc_size]
        count = sym_size // 12
        assert crc_size // 4 == count, f"{crc_name} size mismatch"
        for i in range(count):
            _val_off, name_off, ns_off = struct.unpack_from("<iii", symdata, i * 12)
            name = string_at(sym_addr + i * 12 + 4 + name_off)
            if name is None:
                sys.exit(f"entry {i} of {sym_name}: name address out of range")
            ns = ""
            if ns_off != 0:
                ns = string_at(sym_addr + i * 12 + 8 + ns_off) or ""
            crc = struct.unpack_from("<I", crcdata, i * 4)[0]
            print(f"0x{crc:08x}\t{name}\tvmlinux\t{export}\t{ns}")
        return count

    n = emit("__ksymtab", "__kcrctab", "EXPORT_SYMBOL")
    g = emit("__ksymtab_gpl", "__kcrctab_gpl", "EXPORT_SYMBOL_GPL")
    if n + g == 0:
        sys.exit("no exported symbols found (wrong kernel config?)")
    print(f"gen-symvers: {n} EXPORT_SYMBOL + {g} EXPORT_SYMBOL_GPL = {n + g} total",
          file=sys.stderr)


if __name__ == "__main__":
    main()
