import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'dropin'
RUN.mkdir(parents=True)
temp = RUN / 'temp'
temp.mkdir()
environment = os.environ.copy()
environment['TEMP'] = str(temp)
environment['TMP'] = str(temp)
environment.setdefault('NATIVEMIRROR_SCAN_EXE', str(ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'))
environment.setdefault('NATIVEMIRROR_TARGET32_EXE', str(ROOT / 'bin/Win32/Debug/NativeMirrorTestTarget32.exe'))
environment.setdefault('PESIEVE_EXE', str(ROOT / 'bin/Win64/Debug/pe-sieve64.exe'))
scanner = Path(environment['NATIVEMIRROR_SCAN_EXE'])
reference = Path(environment['PESIEVE_EXE'])
for label, binary, expected in (('native', scanner, b'0.4.1.5'), ('reference', reference, b'0.4.1.1')):
    version = subprocess.run([str(binary), '/version'], capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW, env=environment, cwd=RUN)
    (RUN / (label + '-version.stdout')).write_bytes(version.stdout)
    (RUN / (label + '-version.stderr')).write_bytes(version.stderr)
    if version.returncode != 0 or version.stdout.strip() != expected:
        raise SystemExit('Unexpected version/parser for ' + str(binary) + '. Rebuild NativeMirrorScan before running these checks.')

manifest = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (scanner, reference, ROOT / 'bin/Win64/Debug/NativeMirrorScannerTests.exe')}
(RUN / 'binaries.json').write_text(json.dumps(manifest, indent=2))
results = {}
for filename in ('test_source_contract.py', 'test_runtime_metadata.py', 'test_cli_arguments.py', 'test_dump_contract.py', 'test_pattern_contract.py', 'test_thread_audit.py'):
    command = [sys.executable, str(Path(__file__).parent / filename)]
    result = subprocess.run(command, capture_output=True, timeout=300, cwd=ROOT, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
    (RUN / (filename + '.stdout')).write_bytes(result.stdout)
    (RUN / (filename + '.stderr')).write_bytes(result.stderr)
    results[filename] = result.returncode
    print(filename, 'PASS' if result.returncode == 0 else 'FAIL', flush=True)

integration = RUN / 'integration'
integration.mkdir()
for name in ('NativeMirrorScannerTests.exe', 'NativeMirrorTestTarget.exe'):
    shutil.copyfile(ROOT / 'bin/Win64/Debug' / name, integration / name)
result = subprocess.run([str(integration / 'NativeMirrorScannerTests.exe')], capture_output=True, timeout=300, cwd=ROOT, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
(integration / 'console.txt').write_bytes(result.stdout + result.stderr)
(integration / 'exitcode.txt').write_text(str(result.returncode))
results['integration'] = result.returncode
(ROOT / 'parity-work/latest-differential-run.txt').write_text(str(integration))
if result.returncode == 0:
    evaluation = subprocess.run([sys.executable, str(ROOT / 'parity-work/evaluate_differential.py')], capture_output=True, timeout=30, cwd=ROOT, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
    (integration / 'evaluation-console.txt').write_bytes(evaluation.stdout + evaluation.stderr)
    results['integration_evaluation'] = evaluation.returncode
(RUN / 'results.json').write_text(json.dumps(results, indent=2))
print('Evidence:', RUN, flush=True)
raise SystemExit(0 if all(code == 0 for code in results.values()) else 1)
