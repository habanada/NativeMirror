import ctypes
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/NativeMirrorDll/finalize_exports.py"
spec = importlib.util.spec_from_file_location("finalize_exports", SCRIPT)
finalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalizer)


class VersionExport(unittest.TestCase):
    def fixture(self, arch):
        path = ROOT / "parity-work" / f"dll-contract-build-{arch}" / "version-fixture/Debug/pe-sieve.dll"
        return path.read_bytes()

    def test_real_pe_data_exports_and_c_imports(self):
        for arch in ("x64", "x86"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory(dir=ROOT / "parity-work") as directory:
                directory = Path(directory)
                dll = directory / "pe-sieve.dll"
                original = self.fixture(arch)
                dll.write_bytes(original)
                consumer = ROOT / "parity-work" / f"dll-contract-build-{arch}" / "Debug/NativeMirrorDllImportContract.exe"
                env = dict(os.environ)
                env["PATH"] = str(directory) + os.pathsep + env.get("PATH", "")
                before = subprocess.run([str(consumer)], cwd=directory, env=env, capture_output=True, timeout=20)
                self.assertEqual(before.returncode, 1)
                build = subprocess.run([sys.executable, str(SCRIPT), str(dll)], capture_output=True, timeout=20)
                self.assertEqual(build.returncode, 0, build.stderr)
                after = subprocess.run([str(consumer)], cwd=directory, env=env, capture_output=True, timeout=20)
                self.assertEqual(after.returncode, 0, after.stderr)
                self.assertIn(b"PASS:", after.stdout)
                self.assertEqual(dll.with_name(dll.name + ".before-version-export").read_bytes(), original)
                self.assertTrue(dll.with_name(dll.name + ".exports.json").is_file())

    def test_only_export_slot_and_checksum_change(self):
        for arch in ("x64", "x86"):
            with self.subTest(arch=arch):
                original = self.fixture(arch)
                output, evidence = finalizer.finalize(original)
                nt, = struct.unpack_from("<I", original, 0x3C)
                checksum = nt + 24 + 64
                slot = evidence["export_slot"]
                allowed = set(range(slot, slot + 4)) | set(range(checksum, checksum + 4))
                self.assertEqual(len(original), len(output))
                actual = {i for i, pair in enumerate(zip(original, output)) if pair[0] != pair[1]}
                self.assertTrue(actual)
                self.assertTrue(actual <= allowed)
                imagehlp = ctypes.WinDLL("imagehlp")
                function = imagehlp.CheckSumMappedFile
                function.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                     ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
                function.restype = ctypes.c_void_p
                header, computed = ctypes.c_uint32(), ctypes.c_uint32()
                buffer = ctypes.create_string_buffer(output)
                self.assertTrue(function(buffer, len(output), ctypes.byref(header), ctypes.byref(computed)))
                self.assertEqual(header.value, computed.value)
                self.assertEqual(finalizer.finalize(output)[0], output)

    def test_wrong_version_or_marker_rejected(self):
        original = self.fixture("x64")
        position = original.index(finalizer.SIGNATURE)
        bad_marker = bytearray(original)
        bad_marker[position] ^= 1
        with self.assertRaises(ValueError):
            finalizer.finalize(bad_marker)
        bad_value = bytearray(original)
        bad_value[position + len(finalizer.SIGNATURE)] ^= 1
        with self.assertRaises(ValueError):
            finalizer.finalize(bad_value)

    def test_wrong_exports_rejected(self):
        original = self.fixture("x64")
        with self.assertRaises(ValueError):
            finalizer.finalize(original.replace(b"PESieve_scan_ex\0", b"PESieve_scan_XX\0"))

    def test_signed_and_truncated_images_rejected(self):
        original = self.fixture("x64")
        nt, = struct.unpack_from("<I", original, 0x3C)
        signed = bytearray(original)
        struct.pack_into("<II", signed, nt + 24 + 112 + 32, len(signed) - 16, 16)
        with self.assertRaises(ValueError):
            finalizer.finalize(signed)
        for length in (0, 2, 64, nt + 24, len(original) // 2):
            with self.subTest(length=length), self.assertRaises(ValueError):
                finalizer.finalize(original[:length])


if __name__ == "__main__":
    unittest.main()
