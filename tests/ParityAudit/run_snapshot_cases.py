import argparse
import datetime
import difflib
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time

from run_console_cases import normalized_console

ROOT = Path(__file__).resolve().parents[2]


def dump_contract(path):
    data = path.read_bytes()
    signature, version, count, directory, checksum, timestamp, flags = struct.unpack_from('<IIIIIIQ', data)
    if signature != 0x504d444d or version & 0xffff != 0xa793 or not flags & 2:
        raise AssertionError('Invalid full-memory minidump: ' + str(path))
    streams = {}
    for index in range(count):
        kind, size, offset = struct.unpack_from('<III', data, directory + 12 * index)
        if offset + size > len(data):
            raise AssertionError('Truncated stream')
        streams[kind] = dict(size=size, offset=offset)
    if 9 not in streams:
        raise AssertionError('Missing Memory64ListStream')
    offset = streams[9]['offset']
    ranges, payload = struct.unpack_from('<QQ', data, offset)
    memory_size = sum(struct.unpack_from('<QQ', data, offset + 16 + index * 16)[1] for index in range(ranges))
    if ranges == 0 or memory_size == 0 or payload + memory_size > len(data):
        raise AssertionError('Missing full-memory payload')
    return dict(flags=flags, stream_types=sorted(streams), full_memory=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reverse', action='store_true')
    parser.add_argument('--module-dumps', action='store_true')
    parser.add_argument('--import-damage', action='store_true')
    options = parser.parse_args()
    options.module_dumps = options.module_dumps or options.import_damage
    run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / ('import-damage' if options.import_damage else ('module-dump-console' if options.module_dumps else 'snapshot-audit'))
    run.mkdir(parents=True)
    programs = [('native', ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'), ('reference', ROOT / 'bin/Win64/Debug/pe-sieve64.exe')]
    if options.reverse:
        programs.reverse()
    target = ROOT / 'bin/Win64/Debug/NativeMirrorTestTarget.exe'
    (run / 'binaries.json').write_text(json.dumps({str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [target] + [exe for _, exe in programs]}, indent=2))
    cases = [('MiniClean', 'Clean', False, 1, False, False), ('MiniSuccess', 'CodePatch', False, 1, False, False), ('MiniQuiet', 'CodePatch', True, 1, False, False), ('MiniFullQuiet', 'CodePatch', True, 0, False, False), ('MiniBlocked', 'CodePatch', False, 1, True, False), ('MiniBlockedQuiet', 'CodePatch', True, 1, True, False), ('MiniNoDir', 'CodePatch', False, 2, False, False), ('ReflectClean', 'Clean', False, 2, False, True), ('ReflectPatch', 'CodePatch', False, 2, False, True), ('ReflectPrivate', 'PrivateExecutable', False, 2, False, True), ('ReflectQuiet', 'CodePatch', True, 2, False, True)]
    extras = {}
    if options.module_dumps:
        cases = [('DumpClean', 'Clean', False, 0, False, False), ('DumpPatch', 'CodePatch', False, 0, False, False), ('DumpQuiet', 'CodePatch', True, 0, False, False), ('DumpPrivatePe', 'PrivatePe', False, 0, False, False), ('DumpPrivateCode', 'PrivateExecutable', False, 0, False, False), ('DumpIat', 'IatRedirect', False, 0, False, False), ('DumpBlocked', 'CodePatch', False, 0, True, False), ('DumpBlockedQuiet', 'CodePatch', True, 0, True, False), ('DumpNoDumps', 'CodePatch', False, 1, False, False), ('DumpNoDir', 'CodePatch', False, 2, False, False)]
        extras['DumpIat'] = ['/iat', '1']
        for name, option, values in [('Mode', 'dmode', range(1, 4)), ('Import', 'imp', range(1, 6))]:
            for value in values:
                case = name + str(value)
                cases.append((case, 'CodePatch', False, 0, False, False))
                extras[case] = ['/' + option, str(value)]
    if options.import_damage:
        cases = []
        for damage in ('no-import', 'bad-rva', 'short-size', 'no-iat', 'neither', 'bad-name', 'no-ilt', 'bad-ilt'):
            for mode in range(6):
                case = damage + '-imp' + str(mode)
                cases.append((case, 'CodePatch', False, 0, False, False))
                extras[case] = ['/imp', str(mode)]
        for damage in ('bad-name', 'bad-ilt'):
            case = damage + '-imp2-quiet'
            cases.append((case, 'CodePatch', True, 0, False, False))
            extras[case] = ['/imp', '2']
    records = []
    for case, scenario, quiet, output_filter, blocked, reflection in cases:
        status = run / (case + '.json')
        process = subprocess.Popen([str(target), '/scenario:' + scenario, '/status:' + str(status)], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline = time.monotonic() + 10
            while not status.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.025)
            info = json.loads(status.read_text(encoding='utf-8-sig'))
            if options.import_damage:
                from import_fixture import damage_import_directory
                patch = damage_import_directory(info['pid'], info['module_path'], case.rsplit('-imp', 1)[0])
                (run / (case + '-patch.json')).write_text(json.dumps(patch, indent=2))
            args = ['/pid', str(info['pid']), '/ofilter', str(output_filter), '/shellc', '1', '/dir', 'output', '/json', '/jlvl', '2', '/report', '5']
            if reflection:
                args.append('/refl')
            elif not options.module_dumps:
                args.append('/minidmp')
            args.extend(extras.get(case, []))
            if scenario == 'PrivateExecutable':
                pattern = run / 'private.sig'
                pattern.write_text('snapshot-private\n16\nDE AD BE EF 13 37 C0 DE 42 24 66 99 A5 5A 7E E7\n', encoding='ascii')
                args.extend(['/pattern', str(pattern)])
            if quiet:
                args.append('/quiet')
            warmup_work = run / case / 'warmup'
            warmup_work.mkdir(parents=True)
            if blocked and not options.module_dumps:
                (warmup_work / 'output' / ('process_' + str(info['pid'])) / (target.name + '.dmp')).mkdir(parents=True)
            warmup = subprocess.run([str(ROOT / 'bin/Win64/Debug/pe-sieve64.exe')] + args + ([] if quiet else ['/quiet']), capture_output=True, timeout=90, cwd=warmup_work, creationflags=subprocess.CREATE_NO_WINDOW)
            (run / (case + '-warmup.stdout')).write_bytes(warmup.stdout)
            (run / (case + '-warmup.stderr')).write_bytes(warmup.stderr)
            if warmup.returncode != (1 if scenario == 'Clean' else 2):
                raise AssertionError('Reference preparation failed: ' + case)
            row = dict(case=case, args=args, warmup_exitcode=warmup.returncode)
            for label, exe in programs:
                work = run / case / label
                work.mkdir(parents=True)
                relative_dump = Path('output') / ('process_' + str(info['pid'])) / (target.name + '.dmp')
                if blocked:
                    if options.module_dumps:
                        raw = warmup.stdout.decode('utf-8-sig')
                        parsed_warmup = json.JSONDecoder().raw_decode(raw[raw.index('{'):])[0]
                        base = parsed_warmup['scan_report']['scans'][0]['code_scan']['module']
                        (work / 'output' / ('process_' + str(info['pid'])) / (base + '.' + target.name)).mkdir(parents=True)
                    else:
                        (work / relative_dump).mkdir(parents=True)
                result = subprocess.run([str(exe)] + args, capture_output=True, timeout=90, cwd=work, creationflags=subprocess.CREATE_NO_WINDOW)
                (work / 'stdout.txt').write_bytes(result.stdout)
                (work / 'stderr.txt').write_bytes(result.stderr)
                stdout = normalized_console(result.stdout).replace(str(work), '<case-work>')
                parsed = json.JSONDecoder().raw_decode(stdout[stdout.index('{'):].replace(str(work).replace('\\', '\\\\'), '<case-work>'))[0]
                parsed.get('scan_report', {}).pop('scanner_version', None)
                if result.returncode != (1 if scenario == 'Clean' else 2):
                    raise AssertionError('Unexpected scan status: ' + case + '/' + label)
                scan_report = parsed['scan_report']
                if scan_report['used_reflection'] != int(reflection):
                    raise AssertionError('Unexpected reflection mode')
                if (scan_report['scanned']['modified']['total'] > 0) != (scenario != 'Clean'):
                    raise AssertionError('Controlled scan classification was not exercised')
                files = sorted(p.relative_to(work / 'output').as_posix() for p in (work / 'output').rglob('*') if p.is_file())
                dump = work / relative_dump
                expected_dump = not options.module_dumps and not reflection and scenario != 'Clean' and output_filter != 2 and not blocked
                if dump.is_file() != expected_dump:
                    raise AssertionError('Unexpected minidump presence: ' + case + '/' + label)
                contract = dump_contract(dump) if dump.is_file() else None
                if reflection and not quiet and '[*] Using process reflection!' not in stdout:
                    raise AssertionError('Reflection was not exercised: ' + label)
                reports = {name: json.loads((work / 'output' / name).read_text(encoding='utf-8-sig').replace(str(work).replace('\\', '\\\\'), '<case-work>')) for name in files if name.endswith('.json')}
                for disk_report in reports.values():
                    disk_report.pop('scanner_version', None)
                if options.import_damage:
                    mode = int(extras[case][1])
                    damage = patch['damage']
                    expected = {0: None, 1: 'IMP_RECREATED_FILTER0', 3: 'IMP_RECREATED_FILTER0', 4: 'IMP_RECREATED_FILTER1', 5: 'IMP_RECREATED_FILTER2'}
                    expected[2] = 'IMP_RECOVERY_ERROR' if damage in ('bad-name', 'bad-ilt') else ('IMP_ALREADY_OK' if damage in ('short-size', 'no-ilt') else 'IMP_DIR_FIXED')
                    dump_reports = [report for name, report in reports.items() if name.endswith('dump_report.json')]
                    if len(dump_reports) != 1 or len(dump_reports[0]['dumps']) != 1:
                        raise AssertionError('Expected one controlled module dump')
                    module_dump = dump_reports[0]['dumps'][0]
                    if module_dump.get('imp_rec_result') != expected[mode] or module_dump['status'] != 1:
                        raise AssertionError('Controlled import recovery branch was not exercised: ' + case + '/' + label)
                contents = {name: hashlib.sha256((work / 'output' / name).read_bytes()).hexdigest() for name in files if not name.endswith(('.json', '.dmp'))}
                row[label] = dict(exitcode=result.returncode, stdout=stdout[:stdout.index('{')], stderr=normalized_console(result.stderr), files=files, reports=reports, contents=contents, dump_contract=contract, report=parsed)
            row['equal'] = row['native'] == row['reference']
            (run / case / 'stdout.diff').write_text(''.join(difflib.unified_diff(row['reference']['stdout'].splitlines(True), row['native']['stdout'].splitlines(True), fromfile='reference', tofile='native')), encoding='utf-8')
            records.append(row)
            print(case, 'PASS' if row['equal'] else 'DIFFERENT', flush=True)
        finally:
            Path(str(status) + '.stop').touch()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    (run / 'results.json').write_text(json.dumps(dict(source_reference='0.4.1.5', runtime_reference='0.4.1.1', normalization=['scanner version/build date', 'CRLF', 'JSON formatting: parsed structurally', 'per-side output working directory', 'elapsed timing values', 'minidump timestamps, stream offsets/sizes, memory ranges and contents: validate full-memory structure instead of byte identity'], cases=records), indent=2))
    print(run)
    return 0 if all(row['equal'] for row in records) else 1


if __name__ == '__main__':
    raise SystemExit(main())
