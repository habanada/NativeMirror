import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def memory_target(case):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    address = kernel.VirtualAlloc(None, 4096, 0x3000, 4)
    if not address:
        raise ctypes.WinError(ctypes.get_last_error())
    if case == 'uniform-128':
        data = bytes(range(128, 256)) * 32
    elif case in ('terminal-prolog32', 'terminal-prolog64'):
        prolog = bytes.fromhex('55 8b ec' if case.endswith('32') else '48 83 e4 f0')
        data = bytes(256) + prolog + bytes(4096 - 256 - len(prolog))
    elif case == 'padded-prolog':
        data = bytes(256) + bytes.fromhex('55 8b ec 90 c3') + bytes(3835)
    elif case == 'unequal-frequency':
        data = bytes([0xff]) + (bytes(range(128, 256)) * 32)[1:]
    else:
        data = bytes(range(128, 256)) * 27 + bytes([0x8b]) * 300 + bytes([0xff]) * 300 + b'WVSAQ\0AQ\0'
    ctypes.memmove(address, data, len(data))
    old = ctypes.c_ulong()
    if not kernel.VirtualProtect(address, 4096, 0x20, ctypes.byref(old)):
        raise ctypes.WinError(ctypes.get_last_error())
    print(json.dumps(dict(pid=os.getpid(), base=hex(address), size=4096)), flush=True)
    sys.stdin.readline()


def scan(exe, args, work):
    work.mkdir(parents=True)
    result = subprocess.run([str(exe)] + args, capture_output=True, timeout=60, cwd=work, creationflags=subprocess.CREATE_NO_WINDOW)
    (work / 'stdout.txt').write_bytes(result.stdout)
    (work / 'stderr.txt').write_bytes(result.stderr)
    raw = result.stdout.decode('utf-8-sig')
    report = json.loads(raw[raw.index('{'):raw.rindex('}') + 1])
    scan_report = report.get('scan_report', {})
    scan_report.pop('scanner_version', None)
    output = work / 'output'
    files = {p.relative_to(output).as_posix(): p for p in output.rglob('*') if p.is_file()}
    return dict(exitcode=result.returncode, stderr=result.stderr.decode(errors='replace'), report=report), files


def compare(case, args, run, target_base=None):
    programs = [('native', ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'), ('reference', ROOT / 'bin/Win64/Debug/pe-sieve64.exe')]
    sides = {}
    file_sides = {}
    for label, exe in programs:
        sides[label], file_sides[label] = scan(exe, args, run / case / label)
    files = []
    for name in sorted(set(file_sides['native']) | set(file_sides['reference'])):
        if name.endswith('.json'):
            continue
        row = dict(name=name)
        for label in ('native', 'reference'):
            path = file_sides[label].get(name)
            data = path.read_bytes() if path else None
            row[label] = dict(size=len(data), sha256=hashlib.sha256(data).hexdigest(), prefix=data[:20].hex()) if data is not None else None
        row['equal'] = row['native'] == row['reference']
        files.append(row)
    target_reports = {}
    if target_base is not None:
        for label in sides:
            found = []
            for item in sides[label]['report'].get('scan_report', {}).get('scans', []):
                for kind, value in item.items():
                    if isinstance(value, dict) and value.get('module') == format(target_base, 'x'):
                        found.append({kind: value})
            target_reports[label] = found
    if case in ('terminal-prolog32', 'terminal-prolog64'):
        if not any(item.get('workingset_scan', {}).get('has_shellcode') == 1 for item in target_reports.get('reference', [])):
            raise AssertionError('PE-sieve did not detect the controlled terminal prolog: ' + case)
    result = dict(case=case, args=args, target_reports=target_reports, reports_equal=sides['native'] == sides['reference'], files=files)
    if case == 'PrivateThread':
        result['thread_frames'] = {label: [item['thread_scan'].get('thread_info', {}).get('callstack', {}).get('frames_count', 0) for item in sides[label]['report'].get('scan_report', {}).get('scans', []) if 'thread_scan' in item] for label in sides}
        result['thread_schema_version_conflict'] = True
    (run / case / 'comparison.json').write_text(json.dumps(result, indent=2))
    return result


def patch_section_padding(pid, module_path, span=False, all_sections=False):
    import struct
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.VirtualProtectEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    kernel.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]
    handle = kernel.OpenProcess(0x438, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        modules = (ctypes.c_void_p * 1024)()
        needed = ctypes.c_ulong()
        if not psapi.EnumProcessModulesEx(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3):
            raise ctypes.WinError(ctypes.get_last_error())
        data = Path(module_path).read_bytes()
        nt = struct.unpack_from('<I', data, 0x3c)[0]
        optional_size = struct.unpack_from('<H', data, nt + 20)[0]
        count = struct.unpack_from('<H', data, nt + 6)[0]
        alignment = struct.unpack_from('<I', data, nt + 24 + 32)[0]
        patches = []
        for i in range(count):
            offset = nt + 24 + optional_size + i * 40
            name, virtual_size, rva, raw_size = struct.unpack_from('<8sIII', data, offset)
            if not all_sections and name.rstrip(bytes([0])) != b'.text':
                continue
            if all_sections and name.rstrip(bytes([0])) not in (b'.text', b'.data', b'.idata', b'.didata', b'.edata', b'.rdata', b'.pdata'):
                continue
            if all_sections and raw_size - virtual_size < 8:
                continue
            nominal_size = max(virtual_size, raw_size)
            rounded_size = (virtual_size + alignment - 1) // alignment * alignment
            if not all_sections and nominal_size >= rounded_size:
                raise AssertionError('Target has no unused section padding')
            patch_data = bytes.fromhex('55 8b ec 90 c3') if all_sections else bytes([0xcc]) * (16 if span else 1)
            patch_size = len(patch_data)
            patch_offset = virtual_size + 2 if all_sections else (virtual_size + 16 if span else nominal_size)
            if span and patch_offset + patch_size > nominal_size:
                raise AssertionError('Target has no unused raw section padding')
            address = modules[0] + rva + patch_offset
            old = ctypes.c_ulong()
            if not kernel.VirtualProtectEx(handle, address, patch_size, 0x40, ctypes.byref(old)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                written = ctypes.c_size_t()
                if not kernel.WriteProcessMemory(handle, address, ctypes.c_char_p(patch_data), patch_size, ctypes.byref(written)) or written.value != patch_size:
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                previous = ctypes.c_ulong()
                if not all_sections:
                    kernel.VirtualProtectEx(handle, address, patch_size, old.value, ctypes.byref(previous))
            patch = dict(module_base=hex(modules[0]), section_rva=hex(rva), nominal_size=hex(nominal_size), rounded_size=hex(rounded_size), patched_address=hex(address), patch_size=patch_size)
            if not all_sections:
                return patch
            patches.append(patch)
        if len(patches) >= 3:
            return dict(patches=patches)
        raise AssertionError('Target has no .text section')
    finally:
        kernel.CloseHandle(handle)


def main():
    run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'module-audit'
    run.mkdir(parents=True)
    binaries = [ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe', ROOT / 'bin/Win64/Debug/pe-sieve64.exe', ROOT / 'bin/Win64/Debug/NativeMirrorTestTarget.exe']
    (run / 'binaries.json').write_text(json.dumps({str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in binaries}, indent=2))
    results = []
    for case in ('uniform-128', 'padded-prolog', 'unequal-frequency', 'watched-order', 'terminal-prolog32', 'terminal-prolog64'):
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--target', case], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            info = json.loads(process.stdout.readline())
            code_case = case in ('padded-prolog', 'terminal-prolog32', 'terminal-prolog64')
            args = ['/pid', str(info['pid']), '/quiet', '/json', '/jlvl', '2', '/report', '5', '/ofilter', '0', '/dir', 'output', '/shellc', ('1' if code_case else ('2' if case == 'watched-order' else '0')), '/obfusc', '0' if code_case else '1']
            results.append(compare(case, args, run, int(info['base'], 16)))
        finally:
            process.communicate('\n', timeout=10)
    target = ROOT / 'bin/Win64/Debug/NativeMirrorTestTarget.exe'
    for case in ('PrivateExecutable', 'PrivateExecutablePageBoundary', 'PrivateExecutableRegionTail', 'IatRedirect', 'SectionPadding', 'SectionPatchSpan', 'SectionOrder', 'PrivateThread', 'ImportAuto', 'ImportUnerase', 'ImportRebuild0', 'ImportRebuild1', 'ImportRebuild2'):
        status = run / (case + '.json')
        process = subprocess.Popen([str(target), '/scenario:' + ('Clean' if case in ('SectionPadding', 'SectionPatchSpan', 'SectionOrder') else ('CodePatch' if case.startswith('Import') else case)), '/status:' + str(status)], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline = time.monotonic() + 10
            while not status.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.025)
            info = json.loads(status.read_text(encoding='utf-8-sig'))
            if case in ('SectionPadding', 'SectionPatchSpan', 'SectionOrder'):
                patch = patch_section_padding(info['pid'], info['module_path'], case == 'SectionPatchSpan', case == 'SectionOrder')
                (run / (case + '-patch.json')).write_text(json.dumps(patch, indent=2))
            args = ['/pid', str(info['pid']), '/quiet', '/json', '/jlvl', '2', '/report', '5', '/ofilter', '0', '/dir', 'output', '/shellc', '1', '/iat', '1']
            if case.startswith('Import'):
                args.extend(['/imp', str(('ImportAuto', 'ImportUnerase', 'ImportRebuild0', 'ImportRebuild1', 'ImportRebuild2').index(case) + 1)])
            if case == 'PrivateThread':
                args.extend(['/threads', '/report', '7', '/ofilter', '2'])
            if case == 'PrivateThread':
                from thread_evidence import capture_thread_memory
                evidence = capture_thread_memory(info['pid'], int(info['primary_address'], 16))
                (run / 'PrivateThread-memory.json').write_text(json.dumps(evidence, indent=2))
            results.append(compare(case, args, run))
            if case == 'PrivateThread':
                probe_exe = ROOT / 'bin/Win64/Debug/NativeMirrorScannerTests.exe'
                if '--thread-probe'.encode('utf-16-le') not in probe_exe.read_bytes():
                    raise RuntimeError('Rebuild NativeMirrorScannerTests: --thread-probe is missing')
                probe = subprocess.run([str(probe_exe), '--thread-probe', str(info['pid'])], capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
                (run / 'PrivateThread-probe.stdout').write_bytes(probe.stdout)
                (run / 'PrivateThread-probe.stderr').write_bytes(probe.stderr)
                if probe.returncode != 0:
                    raise RuntimeError('Thread context diagnostic failed')
        finally:
            Path(str(status) + '.stop').touch()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    (run / 'results.json').write_text(json.dumps(results, indent=2))
    print(run)
    for result in results:
        print(result['case'], 'reports_equal=' + str(result['reports_equal']), 'unequal_files=' + str(sum(not row['equal'] for row in result['files'])))
    differences = [r['case'] for r in results if not r['reports_equal'] or any(not f['equal'] for f in r['files'])]
    (run / 'assessment.json').write_text(json.dumps(dict(completed_cases=len(results), cases_with_differences=differences, reference_version='0.4.1.1', source_reference_version='0.4.1.5'), indent=2))
    print('PARITY_DIFFERENCES_FOUND' if differences else 'NO_DIFFERENCES_IN_THIS_MATRIX')
    return 1 if differences else 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--target':
        memory_target(sys.argv[2])
    else:
        raise SystemExit(main())
