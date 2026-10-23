import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from run_module_cases import scan

ROOT = Path(__file__).resolve().parents[2]
PROTECTIONS = dict(rw=4, ro=2, rx=0x20, noaccess=1, guardrw=0x104, guardrx=0x120)


def memory_target(protection):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    base = kernel.VirtualAlloc(None, 4096, 0x3000, 4)
    if not base:
        raise ctypes.WinError(ctypes.get_last_error())
    marker = (ctypes.c_ubyte * 16)(0xde, 0xad, 0xbe, 0xef, 0x13, 0x37, 0xc0, 0xde, 0x42, 0x24, 0x66, 0x99, 0xa5, 0x5a, 0x7e, 0xe7)
    ctypes.memmove(base + 256, marker, 16)
    ctypes.memset(ctypes.addressof(marker), 0, 16)
    old = ctypes.c_ulong()

    def protect():
        if not kernel.VirtualProtect(base, 4096, PROTECTIONS[protection], ctypes.byref(old)):
            raise ctypes.WinError(ctypes.get_last_error())

    protect()
    print(json.dumps(dict(pid=os.getpid(), base=base, protection=PROTECTIONS[protection])), flush=True)
    for line in sys.stdin:
        if line.strip() == 'stop':
            break
        if line.strip() == 'reset':
            protect()
            print('ready', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', choices=PROTECTIONS)
    parser.add_argument('--dumps', action='store_true')
    options = parser.parse_args()
    if options.target:
        memory_target(options.target)
        return 0
    run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / ('data-page-dumps' if options.dumps else 'data-pages')
    run.mkdir(parents=True)
    programs = [('native', ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'), ('reference', ROOT / 'bin/Win64/Debug/pe-sieve64.exe')]
    (run / 'binaries.json').write_text(json.dumps({str(p): hashlib.sha256(p.read_bytes()).hexdigest() for _, p in programs}, indent=2))
    pattern = run / 'private.sig'
    pattern.write_text('data-pages-marker\n16\nDE AD BE EF 13 37 C0 DE 42 24 66 99 A5 5A 7E E7\n', encoding='ascii')
    records = []
    cases = [(p, mode, reflection) for p in PROTECTIONS for mode in range(6) for reflection in (False, True)]
    if options.dumps:
        cases = [('rw', 3, False), ('noaccess', 4, False), ('noaccess', 5, True), ('rx', 5, False), ('guardrx', 4, False)]
    for protection, mode, reflection in cases:
        case = protection + '-data' + str(mode) + ('-reflection' if reflection else '-default')
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--target', protection], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            info = json.loads(process.stdout.readline())
            args = ['/pid', str(info['pid']), '/quiet', '/json', '/jlvl', '2', '/report', '5', '/ofilter', ('0' if options.dumps else '2'), '/dir', 'output', '/data', str(mode), '/shellc', '0', '/pattern', str(pattern)]
            if reflection:
                args.append('/refl')
            sides = {}
            file_sides = {}
            for label, exe in programs:
                process.stdin.write('reset\n')
                process.stdin.flush()
                if process.stdout.readline().strip() != 'ready':
                    raise AssertionError('Target did not restore page protection')
                sides[label], files = scan(exe, args, run / case / label)
                if files and not options.dumps:
                    raise AssertionError('NoDir unexpectedly wrote dump files')
                file_sides[label] = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items() if not name.endswith('.json')}
            hits = {}
            for label, side in sides.items():
                report = side['report']['scan_report']
                if report['used_reflection'] != int(reflection or mode >= 4):
                    raise AssertionError('Expected reflection mode was not exercised')
                hits[label] = [item['workingset_scan'] for item in report.get('scans', []) if item.get('workingset_scan', {}).get('module') == format(info['base'], 'x')]
            expected = (protection in ('rw', 'ro') and mode in (3, 4)) or protection == 'rx' or (protection == 'noaccess' and mode >= 4)
            if len(hits['reference']) != int(expected):
                raise AssertionError('Reference fixture classification changed: ' + case + ' ' + str(hits['reference']))
            if expected and hits['reference'][0]['has_shellcode'] != 1:
                raise AssertionError('Reference did not match controlled signature')
            if options.dumps and expected:
                expected_name = 'process_' + str(info['pid']) + '/' + format(info['base'], 'x') + '.shc'
                if expected_name not in file_sides['reference']:
                    raise AssertionError('Reference did not dump the controlled page')
                payload = (run / case / 'reference/output' / expected_name).read_bytes()
                marker = bytes.fromhex('DE AD BE EF 13 37 C0 DE 42 24 66 99 A5 5A 7E E7')
                if len(payload) != 4096 or payload[256:272] != marker:
                    raise AssertionError('Reference did not retain controlled marker in full page dump')
            row = dict(case=case, args=args, target=info, expected_target_detected=expected, target_reports=hits, files=file_sides, equal=sides['native'] == sides['reference'] and file_sides['native'] == file_sides['reference'])
            (run / case / 'comparison.json').write_text(json.dumps(row, indent=2))
            records.append(row)
            print(case, 'PASS' if row['equal'] else 'DIFFERENT', flush=True)
        finally:
            process.communicate('stop\n', timeout=10)
    (run / 'results.json').write_text(json.dumps(dict(source_reference='0.4.1.5', runtime_reference='0.4.1.1', normalization=['scanner version only; JSON structural'], cases=records), indent=2))
    print(run)
    return 0 if all(row['equal'] for row in records) else 1


if __name__ == '__main__':
    raise SystemExit(main())
