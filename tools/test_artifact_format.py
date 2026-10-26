#!/usr/bin/env python3
"""Tests for tools/artifact_format.py - content-based binary format routing.

Hermetic: every fixture is a synthetic byte blob built in a temp dir (zip
containers via the stdlib zipfile module, PE/ELF/Mach-O/class files from
hand-packed headers). No network, no external tools, no real decompilers.
Run: python3 tools/test_artifact_format.py  (unittest.main(verbosity=2)).
"""
import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from artifact_format import sniff, main  # noqa: E402


def make_zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, blob in members:
            z.writestr(name, blob)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def p(self, name):
        return os.path.join(self.dir, name)


class TestZipFamily(TempDirTest):
    def test_apk(self):
        p = self.p("app.apk")
        make_zip(p, [("AndroidManifest.xml", b"\x03\x00"),
                     ("classes.dex", b"dex\x0a")])
        r = sniff(p)
        self.assertEqual(r["format"], "apk")

    def test_apk_renamed_to_bin(self):
        """Routing keys off content, not extension."""
        p = self.p("mystery.bin")
        make_zip(p, [("AndroidManifest.xml", b""), ("classes.dex", b"")])
        self.assertEqual(sniff(p)["format"], "apk")

    def test_aab_wins_over_apk_marker(self):
        """A bundle carries AndroidManifest.xml too; BundleConfig.pb must win."""
        p = self.p("app.aab")
        make_zip(p, [("AndroidManifest.xml", b""), ("BundleConfig.pb", b""),
                     ("base/dex/classes.dex", b"")])
        self.assertEqual(sniff(p)["format"], "aab")

    def test_apks_split_bundle(self):
        p = self.p("splits.apks")
        make_zip(p, [("split_config.arm64_v8a.apk", b""), ("untouched", b"x")])
        self.assertEqual(sniff(p)["format"], "apks")

    def test_ipa(self):
        p = self.p("app.ipa")
        make_zip(p, [("Payload/DVBA.app/Info.plist", b""),
                     ("Payload/DVBA.app/DVBA", b"\xfe\xed\xfa\xcf")])
        self.assertEqual(sniff(p)["format"], "ipa")

    def test_dex_only_zip(self):
        p = self.p("blob.zip")
        make_zip(p, [("classes.dex", b"dex")])
        self.assertEqual(sniff(p)["format"], "apk")

    def test_jar(self):
        p = self.p("lib.jar")
        make_zip(p, [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                     ("com/example/Main.class", b"\xca\xfe\xba\xbe")])
        self.assertEqual(sniff(p)["format"], "jar")

    def test_plain_zip(self):
        p = self.p("doc.zip")
        make_zip(p, [("readme.txt", b"hi"), ("data/", b"")])
        r = sniff(p)
        self.assertEqual(r["format"], "zip")

    def test_unreadable_zip_struct(self):
        p = self.p("broken.zip")
        with open(p, "wb") as fh:  # local-header magic, corrupt central dir
            fh.write(b"PK\x03\x04" + b"\x00" * 60)
        self.assertEqual(sniff(p)["format"], "zip")


class TestPEFamily(TempDirTest):
    def _pe(self, name, machine=0x8664, pe32plus=True, ndirs=16, clr_size=0,
            opt_magic=None):
        p = self.p(name)
        dirs = 112 if pe32plus else 96
        opt_magic = opt_magic or (0x20B if pe32plus else 0x10B)
        opt = bytearray(b"\x00" * dirs)
        struct.pack_into("<H", opt, 0, opt_magic)
        struct.pack_into("<I", opt, dirs - 4, ndirs)  # NumberOfRvaAndSizes
        dd = bytearray(ndirs * 8)
        if ndirs > 14:
            struct.pack_into("<II", dd, 14 * 8, 0x2000, clr_size)
        blob = bytearray(b"MZ" + b"\x00" * 0x3E)  # 64-byte DOS header
        e_lfanew = 0x80
        struct.pack_into("<I", blob, 0x3C, e_lfanew)
        blob += b"\x00" * (e_lfanew - len(blob)) + b"PE\x00\x00"
        blob += struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, dirs, 0x22)  # 20-byte COFF
        blob += opt + dd
        with open(p, "wb") as fh:
            fh.write(bytes(blob))
        return p

    def test_dotnet_pe32plus(self):
        r = sniff(self._pe("app.dll", clr_size=72))
        self.assertEqual(r["format"], "dotnet")
        self.assertEqual(r["arch"], "x86_64")
        self.assertEqual(r["bits"], 64)

    def test_dotnet_pe32(self):
        r = sniff(self._pe("net48.exe", machine=0x014C, pe32plus=False, clr_size=72))
        self.assertEqual(r["format"], "dotnet")
        self.assertEqual(r["bits"], 32)

    def test_plain_pe(self):
        r = sniff(self._pe("tool.exe"))
        self.assertEqual(r["format"], "pe")
        self.assertEqual(r["arch"], "x86_64")

    def test_pe_ndirs_exactly_15_marks_dotnet(self):
        """COM descriptor directory index 14 requires NumberOfRvaAndSizes >= 15."""
        r = sniff(self._pe("edge.exe", ndirs=15, clr_size=8))
        self.assertEqual(r["format"], "dotnet")

    def test_pe_ndirs_14_not_dotnet(self):
        r = sniff(self._pe("legacy.exe", ndirs=14, clr_size=8))
        self.assertEqual(r["format"], "pe")

    def test_dotnet_renamed(self):
        r = sniff(self._pe("noext", clr_size=72))
        self.assertEqual(r["format"], "dotnet")

    def test_mz_stale_lfanew(self):
        """Garbage e_lfanew still routes to pe (no crash, no detail claims)."""
        p = self.p("stub.mz")
        with open(p, "wb") as fh:
            fh.write(b"MZ" + struct.pack("<I", 0x7FFFFFFF) + b"\x00" * 0x100)
        r = sniff(p)
        self.assertEqual(r["format"], "pe")
        self.assertIn("implausible", r["detail"])


class TestELF(TempDirTest):
    def _elf(self, name, machine, ei_class=2, ei_data=1):
        p = self.p(name)
        ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
        end = "<" if ei_data == 1 else ">"
        blob = ident + struct.pack(end + "HHI", 2, machine, 1) + b"\x00" * 40
        with open(p, "wb") as fh:
            fh.write(blob)
        return p

    def test_elf_aarch64(self):
        r = sniff(self._elf("libcheck.so", 183))
        self.assertEqual(r["format"], "elf")
        self.assertEqual(r["arch"], "aarch64")
        self.assertEqual(r["bits"], 64)
        self.assertEqual(r["endian"], "little")

    def test_elf_arm32(self):
        r = sniff(self._elf("libtool.so", 40, ei_class=1))
        self.assertEqual(r["arch"], "arm")
        self.assertEqual(r["bits"], 32)

    def test_elf_big_endian(self):
        r = sniff(self._elf("mips.bin", 8, ei_data=2))
        self.assertEqual(r["arch"], "mips")
        self.assertEqual(r["endian"], "big")

    def test_elf_unknown_machine(self):
        r = sniff(self._elf("odd.so", 0xABCD))
        self.assertEqual(r["format"], "elf")
        self.assertIn("machine-", r["arch"])


class TestMachO(TempDirTest):
    def test_thin_arm64_be(self):
        p = self.p("dvba")
        with open(p, "wb") as fh:
            fh.write(b"\xfe\xed\xfa\xcf" + struct.pack(">I", 0x0100000C) + b"\x00" * 16)
        r = sniff(p)
        self.assertEqual(r["format"], "macho")
        self.assertEqual(r["arch"], "arm64")
        self.assertEqual(r["bits"], 64)
        self.assertEqual(r["endian"], "big")

    def test_thin_x86_le_cigam(self):
        p = self.p("i386.bin")
        with open(p, "wb") as fh:
            fh.write(b"\xce\xfa\xed\xfe" + struct.pack("<I", 7) + b"\x00" * 16)
        r = sniff(p)
        self.assertEqual(r["format"], "macho")
        self.assertEqual(r["arch"], "x86")
        self.assertEqual(r["endian"], "little")
        self.assertEqual(r["bits"], 32)

    def test_fat_two_archs(self):
        p = self.p("universal")
        fat = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
        fat += struct.pack(">IIIII", 0x0100000C, 0, 0x1000, 0, 16)  # arm64
        fat += struct.pack(">IIIII", 7, 0, 0x2000, 0, 16)           # x86
        with open(p, "wb") as fh:
            fh.write(fat)
        r = sniff(p)
        self.assertEqual(r["format"], "macho_fat")
        self.assertIn("arm64", r["detail"])
        self.assertIn("x86", r["detail"])


class TestJavaClass(TempDirTest):
    def test_java_class(self):
        p = self.p("Main.class")
        with open(p, "wb") as fh:
            fh.write(b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52))
        r = sniff(p)
        self.assertEqual(r["format"], "java_class")
        self.assertEqual(r["bits"], 32)

    def test_cafebabe_major_too_new(self):
        """Major 999 is not a class file -> falls through to fat heuristic."""
        p = self.p("weird")
        with open(p, "wb") as fh:
            fh.write(b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 999))
        r = sniff(p)
        self.assertNotEqual(r["format"], "java_class")


class TestMisc(TempDirTest):
    def test_empty(self):
        p = self.p("empty")
        open(p, "wb").close()
        self.assertEqual(sniff(p)["format"], "unknown")

    def test_text(self):
        p = self.p("note.txt")
        with open(p, "w") as fh:
            fh.write("hello world")
        self.assertEqual(sniff(p)["format"], "unknown")

    def test_main_json_output(self):
        p = self.p("app.apk")
        make_zip(p, [("AndroidManifest.xml", b"")])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([p])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue().strip().splitlines()[-1])
        self.assertEqual(out["format"], "apk")
        self.assertIn("file", out)

    def test_main_usage_missing_file(self):
        self.assertEqual(main([self.p("nope.bin")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
