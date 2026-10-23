import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from test_cli_arguments import normalized

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'patterns'
RUN.mkdir(parents=True)
FIRST = RUN / 'first.sig'
SECOND = RUN / 'second.sig'
EMPTY = RUN / 'empty.sig'
MISSING = RUN / 'missing.sig'
FIRST.write_bytes(b'pattern_a\n4\nDE AD BE EF\n')
SECOND.write_bytes(b'pattern_b\n4\nCA FE BA BE\n')
EMPTY.write_bytes(b'')
NATIVE = Path(os.environ.get('NATIVEMIRROR_SCAN_EXE', ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'))
REFERENCE = Path(os.environ.get('PESIEVE_EXE', ROOT / 'bin/Win64/Debug/pe-sieve64.exe'))
RUNNER = ROOT / 'bin/Win64/Debug/NativeMirrorScannerTests.exe'
(RUN / 'binaries.json').write_text(json.dumps({str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (NATIVE, REFERENCE, RUNNER)}, indent=2))


class PatternCliContract(unittest.TestCase):
    def test_load_messages_before_open(self):
        records = []
        for case, pattern, quiet, expected in (('valid-quiet', FIRST, True, 1), ('empty-quiet', EMPTY, True, 0), ('missing-quiet', MISSING, True, 0), ('valid-verbose', FIRST, False, 1), ('empty-verbose', EMPTY, False, 0), ('missing-verbose', MISSING, False, 0)):
            args = ['/pid', '0', '/ofilter', '2', '/pattern', str(pattern)] + (['/quiet'] if quiet else [])
            row = dict(case=case, args=args)
            for label, exe in (('native', NATIVE), ('reference', REFERENCE)):
                work = RUN / case / label
                work.mkdir(parents=True)
                result = subprocess.run([str(exe)] + args, capture_output=True, timeout=20, cwd=work, creationflags=subprocess.CREATE_NO_WINDOW)
                (work / 'stdout.txt').write_bytes(result.stdout)
                (work / 'stderr.txt').write_bytes(result.stderr)
                row[label] = dict(exitcode=result.returncode, stdout=normalized(result.stdout), stderr=normalized(result.stderr))
            records.append(row)
            (RUN / 'cli-cases.json').write_text(json.dumps(records, indent=2))
            with self.subTest(case=case, field='reference-load-count'):
                self.assertIn(f'Added patterns: {expected}\n', row['reference']['stdout'])
            with self.subTest(case=case, field='parity'):
                self.assertEqual(row['reference'], row['native'])

    def test_custom_signature_detection_and_dump(self):
        sys.path.insert(0, str(ROOT / 'tests/ParityAudit'))
        import run_module_cases
        code = RUN / 'custom-code.sig'
        code.write_bytes(b'custom_code\n5\n55 8B EC 90 C3\n')
        process = subprocess.Popen([sys.executable, str(ROOT / 'tests/ParityAudit/run_module_cases.py'), '--target', 'padded-prolog'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            info = json.loads(process.stdout.readline())
            args = ['/pid', str(info['pid']), '/quiet', '/json', '/jlvl', '2', '/report', '5', '/ofilter', '0', '/dir', 'output', '/shellc', '0', '/pattern', str(code)]
            result = run_module_cases.compare('custom-code', args, RUN, int(info['base'], 16))
            reports = result['target_reports']['reference']
            self.assertTrue(any(item.get('workingset_scan', {}).get('patterns', {}).get('custom_matched') == 1 for item in reports), 'Reference must actually detect the custom signature')
            self.assertTrue(result['reports_equal'])
            self.assertTrue(result['files'])
            self.assertTrue(all(row['equal'] for row in result['files']))
        finally:
            process.communicate('\n', timeout=10)


class PatternLibraryContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if '--pattern-probe'.encode('utf-16-le') not in RUNNER.read_bytes():
            raise RuntimeError('Rebuild NativeMirrorScannerTests: isolated pattern probes are not in this binary')

    def probe(self, mode, first=FIRST, second=SECOND):
        work = RUN / mode
        work.mkdir()
        result = subprocess.run([str(RUNNER), '--pattern-probe', mode, str(first), str(second)], capture_output=True, timeout=30, cwd=work, creationflags=subprocess.CREATE_NO_WINDOW)
        (work / 'stdout.txt').write_bytes(result.stdout)
        (work / 'stderr.txt').write_bytes(result.stderr)
        self.assertEqual(0, result.returncode, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
        self.assertEqual(b'', result.stderr)
        data = json.loads(result.stdout.decode('utf-8-sig'))
        self.assertEqual(mode, data['mode'])
        for scan in data['scans']:
            if mode == 'valid_scans':
                self.assertFalse(scan['open_failed'])
                self.assertTrue(scan['target_detected'], 'The retained first signature must detect the real private executable page')
            else:
                self.assertTrue(scan['open_failed'], 'Invalid PID must still consume initialization before OpenProcess')
        return data

    def test_file_once(self):
        scans = self.probe('file_once')['scans']
        self.assertEqual(['I:Added patterns: 1'], scans[0]['messages'])
        self.assertEqual([[], []], [scan['messages'] for scan in scans[1:]])
        self.assertEqual([(1, 0, 0)] * 3, [(s['a'], s['b'], s['prolog']) for s in scans])

    def test_retained_signature_detects_across_real_scans(self):
        scans = self.probe('valid_scans')['scans']
        self.assertEqual(['I:Added patterns: 1'], scans[0]['messages'])
        self.assertEqual([[], []], [scan['messages'] for scan in scans[1:]])
        self.assertEqual([(1, 0, 0)] * 3, [(s['a'], s['b'], s['prolog']) for s in scans])

    def test_missing_attempt_is_consumed(self):
        scans = self.probe('missing_first', MISSING, SECOND)['scans']
        self.assertEqual(['I:Added patterns: 0'], scans[0]['messages'])
        self.assertEqual([], scans[1]['messages'])
        self.assertEqual([(0, 0, 0)] * 2, [(s['a'], s['b'], s['prolog']) for s in scans])

    def test_builtins_once(self):
        scans = self.probe('builtin_once')['scans']
        self.assertEqual([1, 1, 1], [s['prolog'] for s in scans])
        self.assertTrue(all(s['messages'] == [] for s in scans))

    def test_builtins_do_not_consume_file_attempt(self):
        scans = self.probe('builtin_then_file')['scans']
        self.assertEqual([(0, 0, 1), (1, 0, 1), (1, 0, 1)], [(s['a'], s['b'], s['prolog']) for s in scans])
        self.assertEqual(['I:Added patterns: 1'], scans[1]['messages'])
        self.assertEqual([], scans[2]['messages'])

    def test_file_does_not_consume_builtins(self):
        scans = self.probe('file_then_builtin')['scans']
        self.assertEqual([(1, 0, 0), (1, 0, 1)], [(s['a'], s['b'], s['prolog']) for s in scans])

    def test_repeated_verbose_reports_zero_new_patterns(self):
        scans = self.probe('verbose')['scans']
        first = [s for s in scans[0]['messages'] if s.startswith(('I:Added patterns:', 'I:[+] Pattern file', 'E:[-] Failed to load pattern'))]
        second = [s for s in scans[1]['messages'] if s.startswith(('I:Added patterns:', 'I:[+] Pattern file', 'E:[-] Failed to load pattern'))]
        self.assertEqual(['I:Added patterns: 1', 'I:[+] Pattern file loaded: ' + str(FIRST) + ', Signs: 1'], first)
        self.assertEqual(['E:[-] Failed to load pattern file: ' + str(SECOND)], second)
        self.assertEqual((1, 0), (scans[1]['a'], scans[1]['b']))

    def test_parallel_initialization(self):
        data = self.probe('concurrent')
        self.assertEqual(['Added patterns: 1'], data['messages'])
        self.assertEqual((1, 0, 1), (data['a'], data['b'], data['prolog']))


if __name__ == '__main__':
    print('Pattern evidence:', RUN, flush=True)
    unittest.main()
