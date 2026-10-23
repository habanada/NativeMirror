import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]


def read_report(path):
    raw = path.read_text(encoding='utf-8-sig')
    return json.loads(raw[raw.index('{'):raw.rindex('}') + 1])['scan_report']


def main():
    run = Path(sys.argv[1]) if len(sys.argv) > 1 else max((ROOT / 'parity-work/runs').glob('*/module-audit'))
    source = ROOT / 'pe-sieve-master/pe-sieve-master/scanners/thread_scanner.h'
    source_text = source.read_text()
    for token in ('"thread_info"', '"susp_areas"', '"native_callstack"'):
        if token.replace('"', '\\"') not in source_text:
            raise AssertionError('Unexpected 0.4.1.5 source contract: ' + token)
    reports = {label: read_report(run / 'PrivateThread' / label / 'stdout.txt') for label in ('native', 'reference')}
    threads = {label: {item['thread_scan']['thread_id']: item['thread_scan'] for item in reports[label]['scans'] if 'thread_scan' in item} for label in reports}
    errors = []
    observations = []
    compared = 0
    for tid, thread in threads['native'].items():
        if not set(thread).issubset({'status', 'thread_id', 'thread_info', 'indicators', 'susp_areas'}):
            errors.append(f'{tid}: root fields do not match the local 0.4.1.5 schema')
        if type(thread.get('status')) is not int or type(thread.get('thread_id')) is not int:
            errors.append(f'{tid}: numeric status/thread_id missing')
        if not isinstance(thread.get('indicators'), list):
            errors.append(f'{tid}: indicators array missing')
        info = thread.get('thread_info', {})
        if not isinstance(info.get('state'), str):
            errors.append(f'{tid}: state missing')
        for name in ('callstack', 'native_callstack'):
            stack = info.get(name)
            if stack is not None:
                if not re.fullmatch('[0-9a-f]+', stack.get('stack_ptr', '')):
                    errors.append(f'{tid}: {name} stack pointer invalid')
                if type(stack.get('frames_count')) is not int or stack['frames_count'] != len(stack.get('frames', [])):
                    errors.append(f'{tid}: {name} frame count/list mismatch at JSON detail level 2')
        reference = threads['reference'].get(tid)
        if reference is None:
            continue
        reference_info = reference.get('thread_info', {})
        stable = info.get('state') == reference_info.get('state') == 'Waiting' and info.get('wait_reason') == reference_info.get('wait_reason')
        if not stable:
            continue
        native_frames = info.get('callstack', {}).get('frames_count', 0)
        reference_frames = reference_info.get('callstack', {}).get('frames_count', 0)
        observations.append(dict(tid=tid, native_frames=native_frames, reference_frames=reference_frames, native_syscall=info.get('last_sysc'), reference_syscall=reference_info.get('last_sysc')))
        if reference_frames:
            compared += 1
            if not native_frames:
                errors.append(f'{tid}: NativeMirror has no frames although PE-sieve obtained frames')
        if reference_info.get('last_sysc') and info.get('last_sysc') != reference_info['last_sysc']:
            errors.append(f'{tid}: last_sysc differs in stable waiting state')
        if thread['status'] != reference['status']:
            errors.append(f'{tid}: classification differs in stable waiting state')
    if compared < 3:
        errors.append('Fewer than three stable thread contexts were compared')
    if reports['native']['scanned'] != reports['reference']['scanned']:
        errors.append('Thread-enabled scan summary differs')
    from thread_evidence import audit_reports
    evidence_path = run / 'PrivateThread-memory.json'
    if evidence_path.exists():
        strict = audit_reports(reports['reference'], reports['native'], json.loads(evidence_path.read_text()))
        if not strict['passed']:
            errors.append('Unexpected per-field thread differences; inspect strict_audit')
    else:
        strict = dict(passed=False, reason='Independent fixture memory evidence missing')
        errors.append('Independent fixture memory evidence missing')
    result = dict(strict_audit=strict, source_reference='0.4.1.5', runtime_reference='0.4.1.1', known_schema_difference_retained=True, compared_contexts=compared, observations=observations, errors=errors, passed=not errors)
    (run / 'thread-contract.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
