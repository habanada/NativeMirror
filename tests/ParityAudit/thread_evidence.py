from collections import Counter
import copy
import ctypes
import json
import math
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def capture_thread_memory(pid, address):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel.VirtualQueryEx.restype = ctypes.c_size_t

    class Region(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('allocation_base', ctypes.c_void_p), ('allocation_protect', ctypes.c_ulong), ('region_size', ctypes.c_size_t), ('state', ctypes.c_ulong), ('protect', ctypes.c_ulong), ('kind', ctypes.c_ulong)]

    handle = kernel.OpenProcess(0x410, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        region = Region()
        if kernel.VirtualQueryEx(handle, address, ctypes.byref(region), ctypes.sizeof(region)) != ctypes.sizeof(region):
            raise ctypes.WinError(ctypes.get_last_error())
        if region.base != address or region.region_size != 4096:
            raise AssertionError('Unexpected controlled thread region')
        payload = ctypes.create_string_buffer(region.region_size)
        read = ctypes.c_size_t()
        if not kernel.ReadProcessMemory(handle, address, payload, len(payload), ctypes.byref(read)) or read.value != len(payload):
            raise ctypes.WinError(ctypes.get_last_error())
        return dict(base=address, size=region.region_size, alloc_protection=region.allocation_protect, curr_protection=region.protect, bytes=payload.raw.hex())
    finally:
        kernel.CloseHandle(handle)


def differences(reference, native, path=''):
    rows = []
    if type(reference) is not type(native):
        return [dict(path=path, reference=reference, native=native)]
    if isinstance(reference, dict):
        for key in sorted(set(reference) | set(native)):
            if key not in reference or key not in native:
                rows.append(dict(path=path + '/' + key, reference=reference.get(key), native=native.get(key), missing='reference' if key not in reference else 'native'))
            else:
                rows.extend(differences(reference[key], native[key], path + '/' + key))
    elif isinstance(reference, list):
        if len(reference) != len(native):
            rows.append(dict(path=path + '/length', reference=len(reference), native=len(native)))
        for index, (left, right) in enumerate(zip(reference, native)):
            rows.extend(differences(left, right, path + '/' + str(index)))
    elif reference != native:
        rows.append(dict(path=path, reference=reference, native=native))
    return rows


def expected_area(evidence, reference_thread):
    payload = bytes.fromhex(evidence['bytes'])
    trimmed = payload.strip(b'\0')
    start = len(payload) - len(payload.lstrip(b'\0'))
    if not trimmed:
        raise AssertionError('Empty controlled thread payload')
    entropy = -sum((count / len(trimmed)) * math.log2(count / len(trimmed)) for count in Counter(trimmed).values())
    source = (ROOT / 'pe-sieve-master/pe-sieve-master/utils/code_patterns.h').read_text()
    source = re.sub(r'//[^\n]*', '', source)
    arrays = re.findall(r'BYTE\s+\w+\[\]\s*=\s*\{([^}]+)\}', source)
    patterns = [bytes(int(value, 16) for value in re.findall(r'0x([0-9a-fA-F]+)', array)) for array in arrays]
    if len(patterns) != 10:
        raise AssertionError('Unexpected fixed built-in code patterns')
    region = dict(susp_addr=sorted({format(evidence['base'], 'x'), reference_thread['susp_addr']}, key=lambda value: int(value, 16)), module=format(evidence['base'], 'x'), module_size=format(evidence['size'], 'x'), is_code=str(int(any(pattern in trimmed for pattern in patterns))), stats=dict(area_start=format(start, 'x'), area_size=format(len(trimmed), 'x'), entropy=float(format(entropy, '.6g'))))
    if evidence['alloc_protection'] != evidence['curr_protection']:
        region.update(alloc_protection=format(evidence['alloc_protection'], 'x'), curr_protection=format(evidence['curr_protection'], 'x'))
    else:
        region['protection'] = format(evidence['curr_protection'], 'x')
    return region


def audit_reports(reference, native, evidence):
    projected = copy.deepcopy(reference)
    actual = copy.deepcopy(native)
    projected.pop('scanner_version', None)
    actual.pop('scanner_version', None)
    errors = []
    allowed = []
    for index, item in enumerate(projected.get('scans', [])):
        if 'thread_scan' not in item:
            continue
        thread = item['thread_scan']
        prefix = '/scans/' + str(index) + '/thread_scan'
        for name in ('callstack', 'native_callstack'):
            frames = thread.get('thread_info', {}).get(name, {}).get('frames', [])
            for position, frame in enumerate(frames):
                if re.fullmatch('[0-9a-f]+;', frame):
                    frames[position] = frame[:-1]
                    allowed.append(dict(path=prefix + '/thread_info/' + name + '/frames/' + str(position), reason='0.4.1.5 thread_scanner.h emits separator only for a nonempty symbol', reference=frame, expected=frame[:-1]))
        if 'susp_addr' in thread:
            area = expected_area(evidence, thread)
            required_legacy = dict(module=area['module'], module_size=area['module_size'], protection=format(evidence['alloc_protection'], 'x'), stats=dict(area_start=area['stats']['area_start'], area_size=format(int(area['stats']['area_size'], 16) * 2, 'x'), entropy=area['stats']['entropy']))
            for key, value in required_legacy.items():
                if thread.get(key) != value:
                    errors.append(dict(path=prefix + '/' + key, reason='0.4.1.1 controlled legacy value differs from the independently measured fixture', expected=value, actual=thread.get(key)))
            if not evidence['base'] <= int(thread['susp_addr'], 16) < evidence['base'] + evidence['size']:
                errors.append(dict(path=prefix + '/susp_addr', reason='Suspicious address is outside controlled region'))
            for key in ('susp_addr', 'module', 'module_size', 'protection', 'stats'):
                allowed.append(dict(path=prefix + '/' + key, reason='0.4.1.5 SuspAddrReport groups addresses per queried region and fills stats once; values checked against captured memory', reference=thread.pop(key, None)))
            thread['susp_areas'] = [area]
            allowed.append(dict(path=prefix + '/susp_areas', expected=[area], reason='Independent query/protection/bytes/entropy and fixed 0.4.1.5 built-in patterns'))
    raw = differences(reference, native)
    unexpected = differences(projected, actual)
    return dict(raw_differences=raw, permitted_version_changes=allowed, independent_fixture_errors=errors, unexpected_differences=unexpected, passed=not errors and not unexpected)
