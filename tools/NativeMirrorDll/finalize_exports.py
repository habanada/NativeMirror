import argparse
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import os


SIGNATURE = b"NativeMirror.PESieve.Version".ljust(32, b"\0")
VERSION = 0x00040105
EXPORTS = {b"PESieve_help", b"PESieve_scan", b"PESieve_scan_ex", b"PESieve_version"}
DELPHI_RTL_EXPORTS = {b"__dbk_fcall_wrapper", b"dbkFCallWrapperAddr"}


def finalize(data):
    output = bytearray(data)

    def read(format_string, offset):
        size = struct.calcsize(format_string)
        if offset < 0 or offset + size > len(output):
            raise ValueError("PE field outside file")
        return struct.unpack_from(format_string, output, offset)

    if output[:2] != b"MZ":
        raise ValueError("missing MZ header")
    nt, = read("<I", 0x3C)
    if output[nt:nt + 4] != b"PE\0\0":
        raise ValueError("missing PE header")
    machine, section_count = read("<HH", nt + 4)
    optional_size, characteristics = read("<HH", nt + 20)
    if machine not in (0x14C, 0x8664) or not (characteristics & 0x2000):
        raise ValueError("expected x86/x64 DLL")
    optional = nt + 24
    magic, = read("<H", optional)
    directory_offset = {0x10B: 96, 0x20B: 112}.get(magic)
    if directory_offset is None or optional_size < directory_offset + 40:
        raise ValueError("unsupported optional header")
    if (machine == 0x8664) != (magic == 0x20B):
        raise ValueError("machine/optional-header mismatch")
    directory_count, = read("<I", optional + directory_offset - 4)
    if directory_count < 5 or not 1 <= section_count <= 96:
        raise ValueError("invalid directory/section count")
    certificate, certificate_size = read("<II", optional + directory_offset + 32)
    if certificate or certificate_size:
        raise ValueError("refusing to change a signed DLL")
    export_rva, export_size = read("<II", optional + directory_offset)
    sections = []
    for index in range(section_count):
        offset = optional + optional_size + index * 40
        virtual_size, rva, size, raw = read("<IIII", offset + 8)
        flags, = read("<I", offset + 36)
        if raw + size > len(output):
            raise ValueError("section outside file")
        sections.append((rva, size, raw, flags))

    def file_offset(rva, size):
        matches = [raw + rva - base for base, length, raw, flags in sections
                   if base <= rva and rva + size <= base + length]
        if len(matches) != 1:
            raise ValueError("unmapped or ambiguous RVA")
        return matches[0]

    exports = file_offset(export_rva, 40)
    function_count, name_count, functions, names, ordinals = read("<IIIII", exports + 20)
    if function_count != name_count or name_count not in (4, 6):
        raise ValueError("unexpected export count")
    functions = file_offset(functions, function_count * 4)
    names = file_offset(names, name_count * 4)
    ordinals = file_offset(ordinals, name_count * 2)
    found = {}
    for index in range(name_count):
        name_rva, = read("<I", names + index * 4)
        name_offset = file_offset(name_rva, 1)
        end = output.find(b"\0", name_offset, min(len(output), name_offset + 256))
        if end < 0:
            raise ValueError("unterminated export name")
        name = bytes(output[name_offset:end])
        ordinal, = read("<H", ordinals + index * 2)
        if ordinal >= function_count or name in found:
            raise ValueError("invalid export ordinal/name")
        found[name] = functions + ordinal * 4
    if set(found) not in (EXPORTS, EXPORTS | DELPHI_RTL_EXPORTS):
        raise ValueError("unexpected export names")
    if len(set(found.values())) != len(found):
        raise ValueError("aliased export slots")
    candidates = []
    for base, size, raw, flags in sections:
        if flags & 0x20000000 or not flags & 0x40000000:
            continue
        start = raw
        while True:
            offset = output.find(SIGNATURE, start, raw + size)
            if offset < 0:
                break
            value_offset = offset + len(SIGNATURE)
            if value_offset + 4 <= raw + size and read("<I", value_offset)[0] == VERSION:
                candidates.append(base + value_offset - raw)
            start = offset + 1
    if len(candidates) != 1:
        raise ValueError("expected one marked version DWORD in a data section")
    value_rva = candidates[0]
    if export_rva <= value_rva < export_rva + export_size:
        raise ValueError("version data would be interpreted as an export forwarder")
    slot = found[b"PESieve_version"]
    previous_rva, = read("<I", slot)
    if previous_rva != value_rva:
        old_is_code = any(base <= previous_rva < base + size and flags & 0x20000000
                          for base, size, raw, flags in sections)
        if not old_is_code:
            raise ValueError("version export is neither placeholder code nor version data")
        struct.pack_into("<I", output, slot, value_rva)
        checksum_offset = optional + 64
        struct.pack_into("<I", output, checksum_offset, 0)
        checksum = 0
        for offset in range(0, len(output), 2):
            word = output[offset] + ((output[offset + 1] << 8) if offset + 1 < len(output) else 0)
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        struct.pack_into("<I", output, checksum_offset, checksum + len(output))
    return bytes(output), {"machine": machine, "version": VERSION, "version_rva": value_rva,
                           "export_slot": slot, "previous_rva": previous_rva}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dll", type=Path)
    args = parser.parse_args()
    original = args.dll.read_bytes()
    output, evidence = finalize(original)
    checked, _ = finalize(output)
    if checked != output:
        raise ValueError("export verification failed")
    if output != original:
        backup = args.dll.with_name(args.dll.name + ".before-version-export")
        backup.write_bytes(original)
        with tempfile.NamedTemporaryFile(dir=args.dll.parent, prefix=args.dll.name + ".", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(output)
        try:
            os.replace(temporary, args.dll)
        finally:
            if temporary.exists():
                temporary.unlink()
    evidence["sha256"] = hashlib.sha256(output).hexdigest()
    args.dll.with_name(args.dll.name + ".exports.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"PESieve_version: data export verified, RVA 0x{evidence['version_rva']:x}")


if __name__ == "__main__":
    main()
