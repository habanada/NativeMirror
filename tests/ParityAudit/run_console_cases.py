import datetime
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'CLIOutput'))
from test_cli_arguments import normalized

ROOT = Path(__file__).resolve().parents[2]


def normalized_console(raw):
    text = normalized(raw)
    timing = r'(?m)^(\[\*\] (?:Workingset|IATs|Threads) scanned in )\d+ ms\.(?: = [0-9.e+\-]+ sec\.)?(?: = [0-9.e+\-]+ min\.)?$'
    return re.sub(timing, r'\1<elapsed>', text)


def main():
    run = ROOT / 'parity-work/runs' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'console-audit'
    run.mkdir(parents=True)
    programs = [('native', ROOT / 'bin/Win64/Debug/NativeMirrorScan.exe'), ('reference', ROOT / 'bin/Win64/Debug/pe-sieve64.exe')]
    target = ROOT / 'bin/Win64/Debug/NativeMirrorTestTarget.exe'
    (run / 'binaries.json').write_text(json.dumps({str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [target] + [exe for _, exe in programs]}, indent=2))
    records = []
    cases = [('Clean', 'Clean', []), ('CodePatch', 'CodePatch', []), ('IatRedirect', 'IatRedirect', []), ('PrivateExecutable', 'PrivateExecutable', []), ('CleanIgnored', 'Clean', ['/mignore', 'NativeMirrorTestTarget.exe']), ('PrivateThread', 'PrivateThread', ['/threads']), ('QuietClean', 'Clean', ['/quiet'])]
    for case, scenario, extra in cases:
        status = run / (case + '.json')
        process = subprocess.Popen([str(target), '/scenario:' + scenario, '/status:' + str(status)], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline = time.monotonic() + 10
            while not status.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.025)
            info = json.loads(status.read_text(encoding='utf-8-sig'))
            args = ['/pid', str(info['pid']), '/ofilter', '2', '/shellc', '1', '/iat', '1'] + extra
            row = dict(case=case, scenario=scenario, args=args)
            warmup_work = run / case / 'warmup'
            warmup_work.mkdir(parents=True)
            warmup_args = args if '/quiet' in args else args + ['/quiet']
            warmup = subprocess.run([str(programs[1][1])] + warmup_args, capture_output=True, timeout=60, cwd=warmup_work, creationflags=subprocess.CREATE_NO_WINDOW)
            (warmup_work / 'stdout.txt').write_bytes(warmup.stdout)
            (warmup_work / 'stderr.txt').write_bytes(warmup.stderr)
            row['warmup'] = dict(program='reference', args=warmup_args, exitcode=warmup.returncode)
            if warmup.returncode not in (1, 2):
                raise AssertionError('Target preparation scan failed: ' + case)
            for label, exe in programs:
                work = run / case / label
                work.mkdir(parents=True)
                result = subprocess.run([str(exe)] + args, capture_output=True, timeout=60, cwd=work, creationflags=subprocess.CREATE_NO_WINDOW)
                (work / 'stdout.txt').write_bytes(result.stdout)
                (work / 'stderr.txt').write_bytes(result.stderr)
                row[label] = dict(exitcode=result.returncode, stdout=normalized_console(result.stdout), stderr=normalized(result.stderr))
            row['equal'] = row['native'] == row['reference']
            difference = ''.join(difflib.unified_diff(row['reference']['stdout'].splitlines(True), row['native']['stdout'].splitlines(True), fromfile='reference', tofile='native'))
            (run / case / 'stdout.diff').write_text(difference, encoding='utf-8')
            records.append(row)
            print(case, 'PASS' if row['equal'] else 'DIFFERENT', flush=True)
        finally:
            Path(str(status) + '.stop').touch()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    (run / 'results.json').write_text(json.dumps(dict(normalization=['scanner version', 'banner build date', 'CRLF to LF', 'elapsed timing values including conditional seconds/minutes; timing line presence and labels remain strict'], cases=records), indent=2))
    print(run)
    return 0 if all(row['equal'] for row in records) else 1


if __name__ == '__main__':
    raise SystemExit(main())
