import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
BINARIES = [ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe', ROOT / 'bin/Win64/Debug/NativeMirrorScannerTests.exe']
SOURCES = sorted(list((ROOT / 'src').rglob('*.pas')) + list((ROOT / 'src').rglob('*.inc')) + list((ROOT / 'tests/ScannerIntegration/Source').glob('*.pas')) + list((ROOT / 'tests').rglob('*.py')) + [ROOT / 'tests/ScannerIntegration/NativeMirrorScannerTests.dpr', ROOT / 'tools/NativeMirrorScan/NativeMirrorScan.dpr'])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def task(label, command, run):
    result = subprocess.run(command, capture_output=True, timeout=600, cwd=ROOT, creationflags=subprocess.CREATE_NO_WINDOW)
    (run / (label + '.stdout')).write_bytes(result.stdout)
    (run / (label + '.stderr')).write_bytes(result.stderr)
    print(label, 'PASS' if result.returncode == 0 else 'REVIEW', flush=True)
    return dict(label=label, exitcode=result.returncode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wait-for-build', action='store_true')
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--expected-tests', type=int)
    args = parser.parse_args()
    run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'automated-verification'
    run.mkdir(parents=True)
    (ROOT / 'parity-work/latest-automated-verification.txt').write_text(str(run))
    sources = {str(p): sha(p) for p in SOURCES}
    before = {str(p): sha(p) for p in BINARIES}
    (run / 'state.json').write_text(json.dumps(dict(status='waiting' if args.wait_for_build else 'starting', before_binaries=before, source_sha256=sources), indent=2))
    print('Evidence:', run, flush=True)
    if args.wait_for_build:
        print('Waiting for both rebuilt binaries; tests start automatically.', flush=True)
        deadline = time.monotonic() + args.timeout
        stable = None
        stable_count = 0
        while time.monotonic() < deadline:
            if any(sha(Path(p)) != digest for p, digest in sources.items()):
                raise RuntimeError('Source files changed while waiting; restart verification for the final source state')
            try:
                state = [(p.stat().st_mtime_ns, p.stat().st_size, sha(p)) for p in BINARIES]
                changed = all(row[2] != before[str(p)] for p, row in zip(BINARIES, state))
                probes = all(flag.encode('utf-16-le') in BINARIES[1].read_bytes() for flag in ('--pattern-probe', '--thread-probe'))
            except (OSError, PermissionError):
                state, changed, probes = None, False, False
            if changed and probes:
                stable_count = stable_count + 1 if stable == state else 1
                stable = state
                if stable_count >= 3:
                    break
            else:
                stable_count = 0
            time.sleep(2)
        else:
            (run / 'state.json').write_text(json.dumps(dict(status='timed_out', source_sha256=sources), indent=2))
            return 2
    if any(sha(Path(p)) != digest for p, digest in sources.items()):
        raise RuntimeError('Source files changed before test start')
    hashes = {str(p): sha(p) for p in BINARIES}
    (run / 'state.json').write_text(json.dumps(dict(status='running', binary_sha256=hashes, source_sha256=sources), indent=2))
    commands = [('dropin', [sys.executable, str(ROOT / 'tests/CLIOutput/run_dropin_checks.py')]), ('console', [sys.executable, str(ROOT / 'tests/ParityAudit/run_console_cases.py')]), ('modules', [sys.executable, str(ROOT / 'tests/ParityAudit/run_module_cases.py')]), ('artefacts', [sys.executable, str(ROOT / 'tests/ParityAudit/run_artefact_cases.py')]), ('snapshots', [sys.executable, str(ROOT / 'tests/ParityAudit/run_snapshot_cases.py')]), ('dump_console', [sys.executable, str(ROOT / 'tests/ParityAudit/run_snapshot_cases.py'), '--module-dumps']), ('import_damage', [sys.executable, str(ROOT / 'tests/ParityAudit/run_snapshot_cases.py'), '--import-damage']), ('data_pages', [sys.executable, str(ROOT / 'tests/ParityAudit/run_data_pages.py')]), ('data_page_dumps', [sys.executable, str(ROOT / 'tests/ParityAudit/run_data_pages.py'), '--dumps'])]
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(task, label, command, run) for label, command in commands]
        results = [job.result() for job in jobs]
    module_output = (run / 'modules.stdout').read_text(encoding='utf-8-sig')
    module_path = next((Path(line.strip()) for line in module_output.splitlines() if line.strip().endswith('module-audit') and Path(line.strip()).is_dir()), None)
    validated_thread_differences = False
    if module_path:
        thread = task('thread', [sys.executable, str(ROOT / 'tests/ParityAudit/evaluate_thread_contract.py'), str(module_path)], run)
        results.append(thread)
        cases = list(module_path.glob('*/comparison.json'))
        values = [json.loads(p.read_text()) for p in cases]
        different = [r['case'] for r in values if not r['reports_equal'] or any(not f['equal'] for f in r['files'])]
        validated_thread_differences = len(values) == 19 and different == ['PrivateThread'] and thread['exitcode'] == 0 and json.loads((module_path / 'thread-contract.json').read_text())['strict_audit']['passed']
    dropin_output = (run / 'dropin.stdout').read_text(encoding='utf-8-sig')
    dropin_path = next((Path(line.split('Evidence:', 1)[1].strip()) for line in dropin_output.splitlines() if line.startswith('Evidence:') and line.strip().endswith('dropin')), None)
    actual_tests = None
    if dropin_path:
        match = re.search(r'Tests Found\s*:\s*(\d+)', (dropin_path / 'integration/console.txt').read_text(encoding='utf-8-sig'))
        if match:
            actual_tests = int(match[1])
    count_matches = actual_tests is not None and (args.expected_tests is None or args.expected_tests == actual_tests)
    changed_during_tests = any(sha(Path(p)) != digest for p, digest in sources.items()) or any(sha(Path(p)) != digest for p, digest in hashes.items())
    passed = count_matches and not changed_during_tests and all(r['exitcode'] == 0 for r in results if r['label'] != 'modules') and validated_thread_differences
    summary = dict(expected_dunit_tests=args.expected_tests, actual_dunit_tests=actual_tests, test_count_matches=count_matches, status='passed_with_documented_version_differences' if passed else 'review_required', tasks=results, thread_per_field_audit_passed=validated_thread_differences, changed_during_tests=changed_during_tests, binary_sha256=hashes, source_sha256=sources)
    (run / 'state.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
