import ctypes
from pathlib import Path
import struct


def damage_import_directory(pid, module_path, damage):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.VirtualProtectEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    kernel.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]
    data = Path(module_path).read_bytes()
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if struct.unpack_from('<H', data, nt + 24)[0] != 0x20b:
        raise AssertionError('Expected controlled PE64 target')
    directory = nt + 24 + 112
    original_import = data[directory + 8:directory + 16]
    original_iat = data[directory + 96:directory + 104]
    if damage == 'no-import':
        patches = [(directory + 8, bytes(8))]
    elif damage == 'bad-rva':
        patches = [(directory + 8, struct.pack('<II', 0xfffff000, 20))]
    elif damage == 'short-size':
        patches = [(directory + 12, struct.pack('<I', 20))]
    elif damage == 'no-iat':
        patches = [(directory + 96, bytes(8))]
    elif damage == 'neither':
        patches = [(directory + 8, bytes(8)), (directory + 96, bytes(8))]
    elif damage in ('bad-name', 'no-ilt', 'bad-ilt'):
        import_rva = struct.unpack('<II', original_import)[0]
        count = struct.unpack_from('<H', data, nt + 6)[0]
        section_table = nt + 24 + struct.unpack_from('<H', data, nt + 20)[0]
        descriptor_offset = None
        for index in range(count):
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, section_table + 40 * index + 8)
            if rva <= import_rva < rva + raw_size:
                descriptor_offset = raw_offset + import_rva - rva
                break
        if descriptor_offset is None or descriptor_offset + 20 > len(data):
            raise AssertionError('Controlled target has no import descriptor')
        if damage == 'bad-name':
            patches = [(import_rva + 12, struct.pack('<I', 0xfffff000))]
        elif damage == 'no-ilt':
            patches = [(import_rva, bytes(4))]
        else:
            patches = [(import_rva, struct.pack('<I', 0xfffff000))]
    else:
        raise ValueError(damage)
    handle = kernel.OpenProcess(0x438, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        modules = (ctypes.c_void_p * 1024)()
        needed = ctypes.c_ulong()
        if not psapi.EnumProcessModulesEx(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3):
            raise ctypes.WinError(ctypes.get_last_error())
        for offset, payload in patches:
            before = ctypes.create_string_buffer(len(payload))
            read = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, modules[0] + offset, before, len(payload), ctypes.byref(read)) or read.value != len(payload):
                raise ctypes.WinError(ctypes.get_last_error())
            if before.raw == payload:
                raise AssertionError('Controlled mutation would not change memory')
            old = ctypes.c_ulong()
            if not kernel.VirtualProtectEx(handle, modules[0] + offset, len(payload), 4, ctypes.byref(old)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                written = ctypes.c_size_t()
                if not kernel.WriteProcessMemory(handle, modules[0] + offset, ctypes.c_char_p(payload), len(payload), ctypes.byref(written)) or written.value != len(payload):
                    raise ctypes.WinError(ctypes.get_last_error())
                after = ctypes.create_string_buffer(len(payload))
                if not kernel.ReadProcessMemory(handle, modules[0] + offset, after, len(payload), ctypes.byref(read)) or read.value != len(payload) or after.raw != payload:
                    raise AssertionError('Controlled mutation did not reach target memory')
            finally:
                restored = ctypes.c_ulong()
                if not kernel.VirtualProtectEx(handle, modules[0] + offset, len(payload), old.value, ctypes.byref(restored)):
                    raise ctypes.WinError(ctypes.get_last_error())
        return dict(module_base=hex(modules[0]), damage=damage, original_import=original_import.hex(), original_iat=original_iat.hex(), patches=[dict(offset=hex(offset), bytes=payload.hex()) for offset, payload in patches])
    finally:
        kernel.CloseHandle(handle)
