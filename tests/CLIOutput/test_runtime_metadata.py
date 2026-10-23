import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RuntimeMetadataContract(unittest.TestCase):
    def test_clean_targets_at_all_json_levels(self):
        scanner = Path(os.environ.get('NATIVEMIRROR_SCAN_EXE', ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'))
        targets = (
            (ROOT / 'bin/Win64/Debug/NativeMirrorTestTarget.exe', 1),
            (Path(os.environ.get('NATIVEMIRROR_TARGET32_EXE', ROOT / 'bin/Win32/Debug/NativeMirrorTestTarget32.exe')), 0),
        )
        run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'json-metadata'
        run.mkdir(parents=True)
        (run / 'scanner.json').write_text(json.dumps(dict(path=str(scanner), sha256=hashlib.sha256(scanner.read_bytes()).hexdigest()), indent=2))
        for target, bitness in targets:
            status = run / ('target-' + str(bitness) + '.json')
            process = subprocess.Popen([str(target), '/scenario:Clean', '/status:' + str(status)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                deadline = time.monotonic() + 10
                while not status.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.025)
                self.assertTrue(status.exists(), 'Target did not become ready: ' + str(target))
                pid = json.loads(status.read_text(encoding='utf-8-sig'))['pid']
                for level in (0, 1, 2):
                    result = subprocess.run([str(scanner), '/pid', str(pid), '/quiet', '/json', '/jlvl', str(level), '/ofilter', '2'], capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
                    prefix = f'bitness-{bitness}-level-{level}'
                    (run / (prefix + '.stdout')).write_bytes(result.stdout)
                    (run / (prefix + '.stderr')).write_bytes(result.stderr)
                    with self.subTest(target=bitness, level=level, field='exitcode'):
                        self.assertEqual(result.returncode, 1)
                    report = json.loads(result.stdout)['scan_report']
                    for name, expected in (('is_64_bit', bitness), ('is_managed', 0), ('used_reflection', 0)):
                        with self.subTest(target=bitness, level=level, field=name):
                            self.assertIs(type(report[name]), int)
                            self.assertEqual(report[name], expected)
                    with self.subTest(target=bitness, level=level, field='scanner_version'):
                        self.assertIs(type(report.get('scanner_version')), str)
                        self.assertEqual(report['scanner_version'], '0.4.1.5')
            finally:
                Path(str(status) + '.stop').touch()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
        print('Runtime evidence:', run)


if __name__ == '__main__':
    unittest.main()
