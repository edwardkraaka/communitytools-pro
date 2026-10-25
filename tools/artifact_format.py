#!/usr/bin/env python3
"""artifact_format.py - content-based binary format sniffing for the binary lane.

Routes an artifact by its CONTENT (magic bytes + structure), never by filename
or extension. This is the foundation the decompilation lanes key off: an APK
renamed to .bin, a .NET assembly shipped as .dll, or a Mach-O with no extension
all route identically. Modeled on tools/report_ingest.py detect_format (the
repo's prior content-sniffing precedent), extended to the binary universe:

  PK\x03\x04 + AndroidManifest.xml member      -> apk
  PK\x03\x04 + BundleConfig.pb                 -> aab      (Android app bundle)
  PK\x03\x04 + *.apk members / split container -> apks     (xapk/apkm/apks)
  PK\x03\x04 + Payload/*.app                   -> ipa
  PK\x03\x04 + *.dex members                   -> apk      (dex container)
  PK\x03\x04 + MANIFEST.MF + *.class members   -> jar
  PK\x03\x04 (unreadable/other structure)      -> zip
  MZ + PE\0\0 + CLR data directory (index 14)  -> dotnet   (IMAGE_COR20 header)
  MZ                                           -> pe
  \x7fELF                                      -> elf      (+ class/machine)
  FEEDFACE/FEEDFACF (+ LE mirrors)             -> macho    (+ cputype)
  CAFEBEBE-family fat magic (nfat_arch)        -> macho_fat
  CAFE BABE + plausible class major version    -> java_class

The 0xCAFEBABE ambiguity (Java class file vs fat Mach-O header share the same
magic) is resolved the way file(1) does: bytes 4-7 are a plausible Java
major/minor version pair -> java_class, else treat as nfat_arch -> macho_fat.
A 50+-architecture fat binary does not exist in practice; the heuristic is
documented here rather than hidden.

Stdlib only, hermetic (no network, no external tools, no heavy decompilers).
Prints a one-line JSON summary on its last stdout line (house convention).

Usage:
  python3 tools/artifact_format.py <artifact>

Exit codes: 0 = sniffed (format may be "unknown"); 2 = usage/unreadable file.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import zipfile

EXIT_OK = 0
EXIT_USAGE = 2

# --- magic constants ----------------------------------------------------------
ZIP_LOCAL = b"PK\x03\x04"
DOS_MZ = b"MZ"
PE_SIG = b"PE\x00\x00"
ELF_MAGIC = b"\x7fELF"

MACHO_THIN = {
    b"\xfe\xed\xfa\xce": ("big", 32),     # MH_MAGIC
    b"\xce\xfa\xed\xfe": ("little", 32),  # MH_CIGAM
    b"\xfe\xed\xfa\xcf": ("big", 64),     # MH_MAGIC_64
    b"\xcf\xfa\xed\xfe": ("little", 64),  # MH_CIGAM_64
}
FAT_MAGIC = b"\xca\xfe\xba\xbe"
JAVA_MAGIC = b"\xca\xfe\xba\xbe"  # same bytes - disambiguated below

# e_machine -> arch name (ELF)
ELF_MACHINES = {
    3: "x86", 8: "mips", 20: "ppc", 40: "arm", 62: "x86_64", 183: "aarch64",
    243: "riscv", 22: "s390", 76: "loongarch",
}
# COFF machine -> arch name (PE)
PE_MACHINES = {
    0x014C: "x86", 0x8664: "x86_64", 0x01C0: "arm", 0xAA64: "arm64",
}
# Mach-O cputype -> arch name
MACHO_CPUTYPES = {
    7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
}


def _result(fmt, arch=None, bits=None, endian=None, detail=""):
    return {"format": fmt, "arch": arch, "bits": bits, "endian": endian,
            "detail": detail}


def _sniff_zip(head, path):
    """PK\x03\x04: decide apk/aab/apks/ipa/jar/zip from zip member structure."""
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except Exception:
        return _result("zip", detail="zip magic but unreadable/unsupported structure")
    lowers = [n.lower() for n in names]

    def has(prefix_or_suffix):
        return any(n.startswith(prefix_or_suffix) or n.endswith(prefix_or_suffix)
                   for n in lowers)

    # aab check first: an app bundle ALSO carries an AndroidManifest.xml, so the
    # BundleConfig.pb marker must win over the plain-APK marker.
    if has("bundleconfig.pb"):
        return _result("aab", detail="zip + BundleConfig.pb (Android app bundle)")
    if "androidmanifest.xml" in {n.rsplit("/", 1)[-1] for n in lowers}:
        return _result("apk", detail="zip + AndroidManifest.xml member")
    import re
    if any(re.match(r"^payload/[^/]+\.app(/|$)", n) for n in lowers):
        return _result("ipa", detail="zip + Payload/*.app")
    if any(n.endswith(".apk") for n in lowers):
        return _result("apks", detail="zip with embedded .apk members (split bundle)")
    if any(n.endswith(".dex") for n in lowers):
        return _result("apk", detail="zip + dex members")
    if any(n == "meta-inf/manifest.mf" or
           (n.startswith("meta-inf/") and n.endswith(".sf"))
           for n in lowers) and any(n.endswith(".class") for n in lowers):
        return _result("jar", detail="zip + META-INF manifest + .class members")
    return _result("zip", detail="zip, no format-defining members")


def _sniff_mz(data, path):
    """MZ: PE family. CLR runtime header (data directory 14) -> dotnet, else pe."""
    if len(data) < 0x40:
        return _result("pe", bits=16, detail="MZ stub only (DOS header truncated)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    # Sanity: a sane PE offset sits inside the file and below ~4 MB. A garbage
    # e_lfanew (overlay/packed stub) still means "MZ -> PE" per the routing
    # contract, just without COFF detail.
    if not (0 < e_lfanew <= min(len(data) - 0x18, 0x400000)):
        return _result("pe", detail="MZ, PE offset implausible (stub/overlay)")
    if data[e_lfanew:e_lfanew + 4] != PE_SIG:
        return _result("pe", detail="MZ without PE\\0\\0 signature")
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    opt_off = e_lfanew + 24
    if len(data) < opt_off + 2:
        return _result("pe", arch=PE_MACHINES.get(machine), detail="PE, header truncated")
    opt_magic = struct.unpack_from("<H", data, opt_off)[0]
    arch = PE_MACHINES.get(machine)
    if opt_magic == 0x20B:      # PE32+
        bits, dirs_off, ndirs_off = 64, opt_off + 112, opt_off + 108
    elif opt_magic == 0x10B:    # PE32
        bits, dirs_off, ndirs_off = 32, opt_off + 96, opt_off + 92
    else:
        return _result("pe", arch=arch, detail="PE, unknown optional-header magic")
    if len(data) < ndirs_off + 4:
        return _result("pe", arch=arch, bits=bits, detail="PE, optional header truncated")
    ndirs = struct.unpack_from("<I", data, ndirs_off)[0]
    # .NET = a non-empty COM descriptor (CLR runtime header) data directory.
    if ndirs >= 15 and len(data) >= dirs_off + 14 * 8 + 8:
        clr_size = struct.unpack_from("<I", data, dirs_off + 14 * 8 + 4)[0]
        if clr_size > 0:
            return _result("dotnet", arch=arch, bits=bits, endian="little",
                           detail="PE with CLR runtime header (IMAGE_COR20)")
    return _result("pe", arch=arch, bits=bits, endian="little", detail="PE" + ("32+" if bits == 64 else "32"))


def _sniff_elf(data):
    if len(data) < 20:
        return _result("elf", detail="ELF magic, header truncated")
    ei_class, ei_data = data[4], data[5]
    bits = {1: 32, 2: 64}.get(ei_class)
    endian = {1: "little", 2: "big"}.get(ei_data)
    if endian is None:
        return _result("elf", bits=bits, detail="ELF with unknown data encoding")
    e_machine = struct.unpack_from("<H" if endian == "little" else ">H", data, 18)[0]
    arch = ELF_MACHINES.get(e_machine, "machine-%d" % e_machine)
    return _result("elf", arch=arch, bits=bits, endian=endian,
                   detail="ELF %s %s" % (endian, arch))


def _sniff_macho(head):
    magic = head[:4]
    endian, bits = MACHO_THIN[magic]
    cputype = struct.unpack_from("<I" if endian == "little" else ">I", head, 4)[0]
    arch = MACHO_CPUTYPES.get(cputype)
    return _result("macho", arch=arch, bits=bits, endian=endian,
                   detail="Mach-O %s%s" % (arch + " " if arch else "", bits))


def _sniff_cafebabe(head, path):
    """0xCAFEBABE: Java class file (major version in [45, 80]) vs fat Mach-O."""
    if len(head) >= 8:
        minor, major = struct.unpack_from(">HH", head, 4)
        if 45 <= major <= 80:
            return _result("java_class", bits=32, endian="big",
                           detail="Java class file (major %d)" % major)
    if len(head) < 8:
        return _result("unknown", detail="CAFEBABE magic, header truncated")
    nfat = struct.unpack_from(">I", head, 4)[0]
    if nfat > 64:  # absurd architecture count: not a plausible fat header
        return _result("unknown", detail="CAFEBABE with implausible nfat_arch=%d" % nfat)
    archs = []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            hdr = fh.read(8 + nfat * 20)
        for i in range(nfat):
            off = 8 + i * 20
            if len(hdr) < off + 4:
                break
            cputype = struct.unpack_from(">I", hdr, off)[0]
            archs.append(MACHO_CPUTYPES.get(cputype, "cputype-0x%x" % cputype))
    except OSError:
        pass
    return _result("macho_fat", bits=None, endian="big",
                   detail="fat Mach-O (%d arch%s: %s)" % (nfat, "" if nfat == 1 else "es", ", ".join(archs) or "?"))


def sniff(path):
    """Content-sniff `path` -> dict with at least {format, detail}."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if not head:
        return _result("unknown", detail="empty file")
    if head[:4] == ZIP_LOCAL:
        return _sniff_zip(head, path)
    if head[:2] == DOS_MZ:
        with open(path, "rb") as fh:
            data = fh.read(0x400000)  # headers live in the first 4 MB; overlays follow
        return _sniff_mz(data, path)
    if head[:4] == ELF_MAGIC:
        return _sniff_elf(head)
    if head[:4] in MACHO_THIN:
        return _sniff_macho(head)
    if head[:4] == FAT_MAGIC:
        return _sniff_cafebabe(head, path)
    return _result("unknown", detail="no known magic in first %d bytes" % len(head))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Content-based binary format sniffer (magic bytes + structure).")
    ap.add_argument("artifact", help="path to the artifact to sniff")
    args = ap.parse_args(argv)
    if not os.path.isfile(args.artifact):
        print("not a file: %s" % args.artifact, file=sys.stderr)
        return EXIT_USAGE
    try:
        res = sniff(args.artifact)
    except OSError as e:
        print("unreadable: %s" % e, file=sys.stderr)
        return EXIT_USAGE
    res["file"] = args.artifact
    print(json.dumps(res))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
