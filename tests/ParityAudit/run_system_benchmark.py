"""Sequential, paired Windows system scan; raw evidence is retained per PID."""
import argparse
import ctypes
from ctypes import wintypes as w
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import time
import winreg

ROOT = Path(__file__).resolve().parents[2]
KERNEL = ctypes.WinDLL('kernel32', use_last_error=True)
KERNEL.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
KERNEL.OpenProcess.restype = w.HANDLE
KERNEL.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4
KERNEL.CloseHandle.argtypes = [w.HANDLE]
KERNEL.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
KERNEL.CreateToolhelp32Snapshot.restype = w.HANDLE


class ProcessEntry(ctypes.Structure):
    _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('pid', w.DWORD),
                ('heap', ctypes.c_size_t), ('module', w.DWORD), ('threads', w.DWORD),
                ('parent', w.DWORD), ('priority', w.LONG), ('flags', w.DWORD),
                ('name', w.WCHAR * 260)]


KERNEL.Process32FirstW.argtypes = [w.HANDLE, ctypes.POINTER(ProcessEntry)]
KERNEL.Process32NextW.argtypes = [w.HANDLE, ctypes.POINTER(ProcessEntry)]


def identity(pid):
    handle = KERNEL.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        times = [w.FILETIME() for _ in range(4)]
        if not KERNEL.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            return None
        return times[0].dwHighDateTime << 32 | times[0].dwLowDateTime
    finally:
        KERNEL.CloseHandle(handle)


def snapshot():
    handle = KERNEL.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = ProcessEntry()
        entry.size = ctypes.sizeof(entry)
        if not KERNEL.Process32FirstW(handle, ctypes.byref(entry)):
            raise ctypes.WinError(ctypes.get_last_error())
        rows = []
        while True:
            rows.append(dict(pid=entry.pid, name=entry.name, threads=entry.threads,
                             created=identity(entry.pid)))
            if not KERNEL.Process32NextW(handle, ctypes.byref(entry)):
                break
        return sorted(rows, key=lambda row: row['pid'])
    finally:
        KERNEL.CloseHandle(handle)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')


def scan(exe, args, work, timeout):
    work.mkdir(parents=True)
    command = [str(exe)] + args
    started = time.perf_counter()
    try:
        proc = subprocess.run(command, capture_output=True, timeout=timeout, cwd=work,
                              input=b'\n', creationflags=subprocess.CREATE_NO_WINDOW)
        elapsed = time.perf_counter() - started
        stdout, stderr = proc.stdout, proc.stderr
        result = dict(exitcode=proc.returncode, elapsed_s=elapsed, timeout=False)
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b'', exc.stderr or b''
        result = dict(exitcode=None, elapsed_s=time.perf_counter() - started, timeout=True)
    (work / 'stdout.txt').write_bytes(stdout)
    (work / 'stderr.txt').write_bytes(stderr)
    result.update(command=command, stderr_nonempty=bool(stderr))
    raw = stdout.decode('utf-8-sig', errors='replace')
    try:
        payload = json.loads(raw[raw.index('{'):raw.rindex('}') + 1])
        report = payload['scan_report']
        result['summary'] = {key: report.get(key) for key in
                             ('pid', 'is_64_bit', 'is_managed', 'used_reflection', 'scanned')}
        result['scanner_version'] = report.get('scanner_version')
    except (ValueError, KeyError, TypeError) as exc:
        result['parse_error'] = str(exc)
    summary = result.get('summary') or {}
    scanned = summary.get('scanned') or {}
    result['successful'] = (not result['timeout'] and result['exitcode'] in (1, 2)
                            and summary.get('pid') == int(args[1])
                            and scanned.get('total', 0) > 0
                            and scanned.get('errors') == 0)
    save(work / 'measurement.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, default=ROOT / 'bin/Win64/Release/NativeMirrorScan.exe')
    parser.add_argument('--reference', type=Path, default=ROOT / 'bin/Win64/Debug/pe-sieve64.exe')
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--limit', type=int, help='Smoke test only; omit for a system snapshot')
    parser.add_argument('--summarize', type=Path, help='Regenerate a saved run summary without scanning')
    opts = parser.parse_args()
    if opts.summarize:
        run = opts.summarize.resolve()
        records = [json.loads(line) for line in (run / 'records.jsonl').read_text(encoding='utf-8').splitlines()]
        summarize(run, json.loads((run / 'manifest.json').read_text(encoding='utf-8')), records)
        return 0
    if opts.rounds < 1 or opts.timeout <= 0 or (opts.limit is not None and opts.limit < 1):
        parser.error('rounds, timeout and limit must be positive')
    programs = dict(native=opts.native.resolve(), reference=opts.reference.resolve())
    targets = [ROOT / 'bin/Win64/Debug/NativeMirrorTestTarget.exe',
               ROOT / 'bin/Win32/Debug/NativeMirrorTestTarget32.exe']
    for exe in list(programs.values()) + targets:
        if not exe.is_file():
            parser.error('Missing binary: ' + str(exe))
    if programs['native'] == programs['reference'] or programs['native'].read_bytes() == programs['reference'].read_bytes():
        parser.error('Native and reference binaries must differ')
    run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'system-benchmark'
    run.mkdir(parents=True)
    manifest = dict(started=datetime.datetime.now().astimezone().isoformat(),
                    platform=platform.platform(), cpu=platform.processor(), logical_cpus=os.cpu_count(),
                    administrator=bool(ctypes.windll.shell32.IsUserAnAdmin()), rounds=opts.rounds,
                    timeout_s=opts.timeout, limit=opts.limit, binaries={})
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
        manifest['cpu_model'] = winreg.QueryValueEx(key, 'ProcessorNameString')[0].strip()
    for exe in list(programs.values()) + targets:
        manifest['binaries'][str(exe)] = dict(sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                                             size=exe.stat().st_size)
    for label, exe in programs.items():
        version = subprocess.run([str(exe), '/version'], capture_output=True, timeout=10,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        (run / (label + '-version.txt')).write_bytes(version.stdout + version.stderr)
    # Freeze the measured inputs so an IDE rebuild cannot alter a running benchmark.
    frozen = {}
    for label, exe in programs.items():
        destination = run / 'binaries' / label / exe.name
        destination.parent.mkdir(parents=True)
        shutil.copy2(exe, destination)
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        if digest != manifest['binaries'][str(exe)]['sha256']:
            raise RuntimeError('Binary changed while preparing benchmark: ' + str(exe))
        frozen[label] = destination
    programs = frozen
    save(run / 'manifest.json', manifest)
    print('Evidence: ' + str(run), flush=True)
    children = []
    records = []
    try:
        controlled = []
        for i, target in enumerate(targets):
            status = run / ('delphi-target-' + str(i) + '.json')
            child = subprocess.Popen([str(target), '/scenario:Clean', '/status:' + str(status)],
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            children.append((child, status))
            deadline = time.monotonic() + 15
            while not status.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(.05)
            info = json.loads(status.read_text(encoding='utf-8-sig'))
            controlled.append(dict(pid=info['pid'], name=target.name, created=identity(info['pid']),
                                   controlled_delphi=True))
        excluded = {os.getpid()} | {row['pid'] for row in controlled}
        rows = [row for row in snapshot() if row['pid'] not in excluded]
        if opts.limit:
            rows = rows[:opts.limit]
        rows = controlled + rows
        save(run / 'processes.json', rows)
        # Prepare just the controlled fixtures; never hide warmups in timings.
        for row in controlled:
            for label, exe in programs.items():
                scan(exe, ['/pid', str(row['pid']), '/ofilter', '2', '/quiet', '/json'],
                     run / 'warmup' / str(row['pid']) / label, opts.timeout)
        for round_no in range(opts.rounds):
            for index, row in enumerate(rows):
                order = ['native', 'reference'] if (round_no + index) % 2 == 0 else ['reference', 'native']
                record = dict(round=round_no + 1, process=row, order=order)
                before = identity(row['pid'])
                for label in order:
                    record[label] = scan(programs[label], ['/pid', str(row['pid']), '/ofilter', '2',
                                                          '/quiet', '/json'],
                                         run / ('round-' + str(round_no + 1)) / str(row['pid']) / label,
                                         opts.timeout)
                record['stable_identity'] = row['created'] is not None and row['created'] == before == identity(row['pid'])
                record['comparable'] = record['stable_identity'] and all(record[s]['successful'] for s in programs)
                record['summary_equal'] = (record['native'].get('summary') == record['reference'].get('summary')
                                           and record['native']['exitcode'] == record['reference']['exitcode'])
                records.append(record)
                with (run / 'records.jsonl').open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(record, ensure_ascii=False) + '\n')
                if index % 20 == 0 or index == len(rows) - 1:
                    print(f'Round {round_no + 1}/{opts.rounds}: {index + 1}/{len(rows)} pairs', flush=True)
    finally:
        for child, status in children:
            Path(str(status) + '.stop').touch()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        summarize(run, manifest, records)
    return 0


def summarize(run, manifest, records):
    paired = [r for r in records if r['comparable']]
    equal = [r for r in paired if r['summary_equal']]
    rounds = []
    for number in sorted({r['round'] for r in records}):
        subset = [r for r in paired if r['round'] == number]
        sums = {side: sum(r[side]['elapsed_s'] for r in subset) for side in ('native', 'reference')}
        attempts = [r for r in records if r['round'] == number]
        system = [r for r in subset if not r['process'].get('controlled_delphi')]
        rounds.append(dict(round=number, comparable_pairs=len(subset), seconds=sums,
                           all_attempt_seconds={side: sum(r[side]['elapsed_s'] for r in attempts) for side in ('native', 'reference')},
                           comparable_system_pairs=len(system),
                           system_seconds={side: sum(r[side]['elapsed_s'] for r in system) for side in ('native', 'reference')},
                           native_over_reference=sums['native'] / sums['reference'] if sums['reference'] else None))
    result = dict(manifest=manifest, attempted_pairs=len(records), comparable_pairs=len(paired),
                  equal_summaries=len(equal), differing_summaries=len(paired) - len(equal), rounds=rounds,
                  controlled_delphi=[r for r in records if r['process'].get('controlled_delphi')],
                  differences=[r for r in paired if not r['summary_equal']],
                  excluded=[dict(round=r['round'], process=r['process'],
                                 native_success=r['native']['successful'], reference_success=r['reference']['successful'],
                                 stable_identity=r['stable_identity']) for r in records if not r['comparable']])
    processes = json.loads((run / 'processes.json').read_text(encoding='utf-8')) if (run / 'processes.json').exists() else []
    result['expected_pairs'] = len(processes) * manifest['rounds']
    result['complete'] = len(records) == result['expected_pairs'] and bool(processes)
    result['unique_comparable_system_pids'] = len({r['process']['pid'] for r in paired
                                                 if not r['process'].get('controlled_delphi')})
    result['timeouts'] = {side: sum(r[side]['timeout'] for r in records) for side in ('native', 'reference')}
    findings = []
    for row in paired:
        sides = {}
        for side in ('native', 'reference'):
            raw = (run / ('round-' + str(row['round'])) / str(row['process']['pid']) / side / 'stdout.txt').read_text(encoding='utf-8-sig')
            payload = json.loads(raw[raw.index('{'):raw.rindex('}') + 1])
            sides[side] = payload['scan_report'].get('scans')
        findings.append(dict(round=row['round'], process=row['process'], equal=sides['native'] == sides['reference'], **sides))
    save(run / 'finding-comparison.json', findings)
    result['equal_finding_arrays'] = sum(row['equal'] for row in findings)
    result['differing_finding_arrays'] = sum(not row['equal'] for row in findings)
    ratios = [r['native_over_reference'] for r in rounds if r['native_over_reference'] is not None]
    result['median_round_ratio'] = statistics.median(ratios) if ratios else None
    save(run / 'summary.json', result)
    lines = ['# NativeMirror / PE-sieve system snapshot', '',
             f"Attempted pairs: {len(records)}; comparable: {len(paired)}; equal summaries: {len(equal)}; differences: {len(paired) - len(equal)}.", '',
             f"Complete: {result['complete']}; expected pairs: {result['expected_pairs']}; differing finding arrays: {result['differing_finding_arrays']} (strict field/value/order comparison; see finding-comparison.json).", '',
             '| Round | Comparable PIDs | Native seconds | Reference seconds | Native/reference |',
             '| --- | ---: | ---: | ---: | ---: |']
    for row in rounds:
        ratio = row['native_over_reference']
        ratio_text = f'{ratio:.3f}' if ratio is not None else 'n/a'
        lines.append(f"| {row['round']} | {row['comparable_pairs']} | {row['seconds']['native']:.3f} | {row['seconds']['reference']:.3f} | {ratio_text} |")
    lines += ['', '| Round | All native attempts (s) | All reference attempts (s) |',
              '| --- | ---: | ---: |']
    for row in rounds:
        lines.append(f"| {row['round']} | {row['all_attempt_seconds']['native']:.3f} | {row['all_attempt_seconds']['reference']:.3f} |")
    lines += ['', 'Timing includes CLI startup, scanning and JSON serialization. Same initial PID list, serial pairs, alternating first scanner. No dump files (/ofilter 2). Only stable PID creation times and two successful scans with zero reported errors enter timing comparisons. Raw stdout/stderr, commands, timeouts and excluded pairs are retained.', '',
              'This is a live system: memory can change between scans. Summary equality is not full report parity. Shared findings are not automatically false positives. Clean Delphi fixtures are developer test programs, not a representative Delphi application corpus. Python controller is excluded. Administrator status does not guarantee access to protected processes. No synthetic busy workload was added. Check version files and binary paths: Debug/Release and version mismatches prevent a version-matched release performance claim.']
    (run / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Comparable: {len(paired)}, equal: {len(equal)}, differing: {len(paired) - len(equal)}', flush=True)
    print('Summary: ' + str(run / 'summary.md'), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
