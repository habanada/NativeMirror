import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]


def json_output(raw):
    text = raw.decode('utf-8-sig')
    return json.loads(text[text.index('{'):text.rindex('}') + 1])


def normalize_version(report):
    result = copy.deepcopy(report)
    scan = result.get('scan_report', result)
    if 'scanner_version' in scan:
        scan['scanner_version'] = '<scanner-version>'
    return result


class DumpDifferential(unittest.TestCase):
    def test_files_reports_and_output_filters(self):
        native = Path(os.environ.get('NATIVEMIRROR_SCAN_EXE', ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'))
        reference = Path(os.environ.get('PESIEVE_EXE', ROOT / 'bin/Win64/Debug/pe-sieve64.exe'))
        target = ROOT / 'bin/Win64/Debug/NativeMirrorTestTarget.exe'
        run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'dump-contract'
        run.mkdir(parents=True)
        binaries = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (native, reference, target)}
        (run / 'binaries.json').write_text(json.dumps(binaries, indent=2))
        for scenario in ('Clean', 'CodePatch', 'PrivatePe'):
            status = run / (scenario + '.json')
            process = subprocess.Popen([str(target), '/scenario:' + scenario, '/status:' + str(status)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                deadline = time.monotonic() + 10
                while not status.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.025)
                self.assertTrue(status.exists(), 'Target did not become ready')
                pid = json.loads(status.read_text(encoding='utf-8-sig'))['pid']
                for output_filter, report_filter in ((0, 5), (1, 5), (2, 5), (0, 7)):
                    args = ['/pid', str(pid), '/quiet', '/json', '/jlvl', '2', '/report', str(report_filter), '/ofilter', str(output_filter), '/dir', 'output']
                    results = {}
                    for label, exe in (('native', native), ('reference', reference)):
                        work = run / f'{scenario}-ofilter-{output_filter}-report-{report_filter}' / label
                        work.mkdir(parents=True)
                        result = subprocess.run([str(exe)] + args, capture_output=True, timeout=60, cwd=work, creationflags=subprocess.CREATE_NO_WINDOW)
                        (work / 'stdout.txt').write_bytes(result.stdout)
                        (work / 'stderr.txt').write_bytes(result.stderr)
                        output = work / 'output'
                        files = sorted(str(p.relative_to(output)).replace('\\', '/') for p in output.rglob('*') if p.is_file()) if output.exists() else []
                        reports = {name: normalize_version(json.loads((output / name).read_text(encoding='utf-8-sig'))) for name in files if name.endswith('.json')}
                        with self.subTest(scenario=scenario, output_filter=output_filter, report_filter=report_filter, program=label):
                            expected_code = 1 if scenario == 'Clean' else 2
                            self.assertEqual(result.returncode, expected_code)
                            self.assertEqual(result.stderr, b'')
                        contents = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in files if not name.endswith('.json')}
                        results[label] = dict(exitcode=result.returncode, report=normalize_version(json_output(result.stdout)), files=files, reports=reports, contents=contents)
                    with self.subTest(scenario=scenario, output_filter=output_filter, report_filter=report_filter):
                        self.assertEqual(results['reference'], results['native'])
            finally:
                Path(str(status) + '.stop').touch()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
        print('Dump evidence:', run)


if __name__ == '__main__':
    unittest.main()
