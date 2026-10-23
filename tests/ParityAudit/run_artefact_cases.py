import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from run_module_cases import compare

ROOT = Path(__file__).resolve().parents[2]
CASES = ('whole64', 'whole32', 'adjacent64', 'adjacent32', 'gap64', 'gap32', 'wiped-mz64', 'wiped-nt64', 'equal-candidates64')


def image_bytes(base, is64, gap):
    data = bytearray(0x3000)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional_size = 0xf0 if is64 else 0xe0
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664 if is64 else 0x14c, 2, 0, 0, 0, optional_size, 0x23)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x20b if is64 else 0x10b)
    code_rva, data_rva = (0x2000, 0x1000) if gap else (0x1000, 0x2000)
    struct.pack_into('<III', data, opt + 4, 0x1000, 0x1000, 0)
    struct.pack_into('<II', data, opt + 16, code_rva, code_rva)
    if is64:
        struct.pack_into('<Q', data, opt + 24, base)
        struct.pack_into('<QQQQ', data, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into('<I', data, opt + 108, 16)
    else:
        struct.pack_into('<II', data, opt + 24, data_rva, 0x400000)
        struct.pack_into('<IIII', data, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into('<I', data, opt + 92, 16)
    struct.pack_into('<II', data, opt + 32, 0x1000, 0x200)
    struct.pack_into('<HH', data, opt + 40, 6, 0)
    struct.pack_into('<HH', data, opt + 48, 6, 0)
    struct.pack_into('<II', data, opt + 56, 0x3000, 0x400)
    struct.pack_into('<HH', data, opt + 68, 3, 0)
    sections = [(b'.data', data_rva, 0xc0000040), (b'.text', code_rva, 0x60000020)] if gap else [(b'.text', code_rva, 0x60000020), (b'.data', data_rva, 0xc0000040)]
    for i, (name, rva, flags) in enumerate(sections):
        offset = opt + optional_size + i * 40
        struct.pack_into('<8sIIIIIIHHI', data, offset, name, 0x1000, rva, 0x200, 0x400 + i * 0x200, 0, 0, 0, 0, flags)
    data[code_rva:code_rva + 5] = bytes.fromhex('55 8b ec 90 c3')
    return data, code_rva


def target(case):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    size = 0x7000 if case == 'equal-candidates64' else 0x3000
    base = kernel.VirtualAlloc(None, size, 0x3000, 4)
    if not base:
        raise ctypes.WinError(ctypes.get_last_error())
    data, code_rva = image_bytes(base, not case.endswith('32'), case.startswith('gap'))
    if case == 'wiped-mz64':
        data[:2] = bytes(2)
    if case == 'wiped-nt64':
        data[0x80:0x84] = bytes(4)
    ctypes.memmove(base, bytes(data), len(data))
    if case == 'equal-candidates64':
        other, _ = image_bytes(base + 0x4000, True, False)
        ctypes.memmove(base + 0x4000, bytes(other), len(other))
    def protect(address, length, flags):
        old = ctypes.c_ulong()
        if not kernel.VirtualProtect(address, length, flags, ctypes.byref(old)):
            raise ctypes.WinError(ctypes.get_last_error())
    if case.startswith(('adjacent', 'gap')):
        protect(base, 0x1000, 2)
        protect(base + code_rva, 0x1000, 0x20)
    else:
        protect(base, size, 0x20)
    print(json.dumps(dict(pid=os.getpid(), base=base, size=size, code_rva=code_rva)), flush=True)
    sys.stdin.readline()


def main():
    run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'artefact-boundaries'
    run.mkdir(parents=True)
    binaries = [ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe', ROOT / 'bin/Win64/Debug/pe-sieve64.exe']
    (run / 'binaries.json').write_text(json.dumps({str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in binaries}, indent=2))
    results = []
    for case in CASES:
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--target', case], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            info = json.loads(child.stdout.readline())
            (run / (case + '-target.json')).write_text(json.dumps(info, indent=2))
            args = ['/pid', str(info['pid']), '/quiet', '/json', '/jlvl', '2', '/report', '5', '/ofilter', '2', '/shellc', '0']
            result = compare(case, args, run, info['base'])
            reference_hits = result['target_reports']['reference']
            if case.startswith('gap'):
                if reference_hits:
                    raise AssertionError('Reference no longer stops at the controlled gap: ' + case)
            else:
                if len(reference_hits) != 1 or reference_hits[0].get('workingset_scan', {}).get('has_pe') != 1:
                    raise AssertionError('Positive reference fixture was not actually detected: ' + case)
                artefacts = reference_hits[0]['workingset_scan']['pe_artefacts']
                if artefacts['sections_count'] != 2 or artefacts['is_64_bit'] != (0 if case.endswith('32') else 1):
                    raise AssertionError('Unexpected reference header geometry: ' + case)
                if case == 'equal-candidates64' and artefacts['pe_base_offset'] != '0':
                    raise AssertionError('Reference did not retain the first equal-score candidate')
            results.append(result)
            print(case, 'PASS' if result['reports_equal'] and all(f['equal'] for f in result['files']) else 'DIFFERENT', flush=True)
        finally:
            child.communicate('\n', timeout=10)
    (run / 'results.json').write_text(json.dumps(results, indent=2))
    print(run)
    return 0 if all(r['reports_equal'] and all(f['equal'] for f in r['files']) for r in results) else 1


if __name__ == '__main__':
    if len(sys.argv) > 2 and sys.argv[1] == '--target':
        target(sys.argv[2])
    else:
        raise SystemExit(main())
