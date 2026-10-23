import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]


def normalized(raw):
    text = raw.decode('utf-8', 'replace').replace('\r\n', '\n')
    text = re.sub(r'0\.4\.1\.(1|5)\b', '<scanner-version>', text)
    return re.sub(r'(?m)^Built on: .*$', 'Built on: <build-date>', text)


class ArgumentDifferential(unittest.TestCase):
    def test_identical_arguments(self):
        native = Path(os.environ.get('NATIVEMIRROR_SCAN_EXE', ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'))
        reference = Path(os.environ.get('PESIEVE_EXE', ROOT / 'bin/Win64/Debug/pe-sieve64.exe'))
        run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'cli-arguments'
        run.mkdir(parents=True)
        names = ['pid', 'dir', 'mignore', 'pattern', 'data', 'dmode', 'dnet', 'iat', 'imp', 'jlvl', 'obfusc', 'ofilter', 'report', 'shellc', 'json', 'minidmp', 'quiet', 'rebase', 'refl', 'threads']
        cases = [['/version'], ['--ver'], ['-version'], ['/pid'], ['/pid', 'xyz'], ['/PID'], ['/pid:123'], ['/pid=123'], ['/unknown'], ['junk'], ['/help', 'pid'], ['/help', 'version']]
        cases += [[prefix + name, '?'] for prefix in ('/', '-', '--') for name in names]
        enums = {'data': ['0', '1', '2', '3', '4', '5'], 'dmode': ['0', '1', '2', '3', 'A', 'V', 'U', 'R'], 'dnet': ['0', '1', '2', '3', '4'], 'iat': ['0', '1', '2', '3'], 'imp': ['0', '1', '2', '3', '4', '5', 'N', 'A', 'U', 'R0', 'R1', 'R2'], 'jlvl': ['0', '1', '2'], 'obfusc': ['0', '1', '2', '3', 'N', 'S', 'W', 'A'], 'ofilter': ['0', '1', '2'], 'report': ['4', '5', '7', 'S', 'SE', 'L'], 'shellc': ['0', '1', '2', '3', '4', 'N', 'P', 'S', 'A', 'B']}
        for name, values in enums.items():
            for value in values + ['-1', '99', 'xyz', '0x1', '01', '']:
                cases.append(['/' + name, value, '/version'])
        for name in ('json', 'minidmp', 'quiet', 'rebase', 'refl', 'threads'):
            for value in ('0', '1', 'true', 'false', 'on', 'off', 'yes', 'no', 'TRUE', '2', 'xyz', ''):
                cases.append(['/' + name, value, '/version'])
        for value in ('0', '1', '01', '0xFFFFFFFF', '0Xffffffff', '4294967296', '18446744073709551615', '18446744073709551616', '-1', '+1', '$FF', '0x', '1x', ''):
            cases.append(['/pid', value, '/version'])
        cases.extend([['/pid', '0', '/pid', 'xyz'], ['/quiet', 'true', '/quiet', 'false', '/version'], ['/dir', '/quiet', '/version'], ['/pid', '?', '/iat', '?'], ['/unknown', '/version']])
        records = []
        try:
            for index, args in enumerate(cases):
                record = dict(args=args)
                for label, exe in (('native', native), ('reference', reference)):
                    result = subprocess.run([str(exe)] + args, input=b'\n', capture_output=True, timeout=10, cwd=run, creationflags=subprocess.CREATE_NO_WINDOW)
                    (run / f'{index:03}-{label}.stdout').write_bytes(result.stdout)
                    (run / f'{index:03}-{label}.stderr').write_bytes(result.stderr)
                    record[label] = dict(exitcode=result.returncode, stdout=normalized(result.stdout), stderr=normalized(result.stderr))
                records.append(record)
                with self.subTest(index=index, args=args):
                    self.assertEqual(record['reference'], record['native'])
        finally:
            manifest = {str(exe): hashlib.sha256(exe.read_bytes()).hexdigest() for exe in (native, reference)}
            (run / 'results.json').write_text(json.dumps(dict(binary_sha256=manifest, cases=records), indent=2), encoding='utf-8')
            print('Argument evidence:', run)


if __name__ == '__main__':
    unittest.main()
