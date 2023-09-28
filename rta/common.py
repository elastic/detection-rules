# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from __future__ import unicode_literals, print_function

import binascii
import contextlib
import functools
import getpass
import inspect
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Iterable, Optional, Union



    
from http.server import HTTPServer, SimpleHTTPRequestHandler

long_t = type(1 << 63)

HOSTNAME = socket.gethostname()
LOCAL_IP = None


def get_ip() -> str:
    global LOCAL_IP, HOSTNAME

    if LOCAL_IP is None:
        try:
            LOCAL_IP = socket.gethostbyname(HOSTNAME)
        except socket.gaierror:
            LOCAL_IP = "127.0.0.1"

    return LOCAL_IP


def get_winreg():
    try:
        import _winreg as winreg
    except ImportError:
        import winreg
    return winreg


# Multi-OS Support
WINDOWS = "windows"
MACOS = "macos"
LINUX = "linux"

if sys.platform == "darwin":
    CURRENT_OS = MACOS
elif sys.platform.startswith("win"):
    CURRENT_OS = WINDOWS
else:
    CURRENT_OS = LINUX

if CURRENT_OS == WINDOWS:
    CMD_PATH = os.environ.get("COMSPEC")
    POWERSHELL_PATH = "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    import ctypes
    import win32process
    import win32file
    import win32service
    import win32api, win32security
    from ctypes import byref, windll, wintypes
    from ctypes.wintypes import BOOL
    from ctypes.wintypes import DWORD
    from ctypes.wintypes import HANDLE
    from ctypes.wintypes import LPVOID
    from ctypes.wintypes import LPCVOID
    # Windows related constants and classes
    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    TOKEN_DUPLICATE = 0x0002
    TOKEN_ALL_ACCESS = 0xf00ff
    MAX_PATH = 260
    BOOL = ctypes.c_int
    DWORD = ctypes.c_uint32
    HANDLE = ctypes.c_void_p
    LONG = ctypes.c_int32
    NULL_T = ctypes.c_void_p
    SIZE_T = ctypes.c_uint
    TCHAR = ctypes.c_char
    USHORT = ctypes.c_uint16
    UCHAR = ctypes.c_ubyte
    ULONG = ctypes.c_uint32

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ('dwSize', DWORD),
            ('cntUsage', DWORD),
            ('th32ProcessID', DWORD),
            ('th32DefaultHeapID', NULL_T),
            ('th32ModuleID', DWORD),
            ('cntThreads', DWORD),
            ('th32ParentProcessID', DWORD),
            ('pcPriClassBase', LONG),
            ('dwFlags', DWORD),
            ('szExeFile', TCHAR * MAX_PATH)
        ]

    LPCSTR = LPCTSTR = ctypes.c_char_p
    LPDWORD = PDWORD = ctypes.POINTER(DWORD)

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('nLength', DWORD),
                    ('lpSecurityDescriptor', LPVOID),
                    ('bInheritHandle', BOOL), ]

    SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
    LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
    LPTHREAD_START_ROUTINE = LPVOID

else:
    CMD_PATH = "/bin/sh"
    POWERSHELL_PATH = None

BASE_DIR = Path(__file__).resolve().parent
ALL_IP = "0.0.0.0"
IP_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
CALLBACK_REGEX = r"https?://" + IP_REGEX + r":\d+"

USER_NAME = getpass.getuser().lower()

SUCCESS = 0
PYTHON_ERROR = 1  # Python does this internally, so we don't want to overwrite it
GENERAL_ERROR = 2
MISSING_DEPENDENCIES = 3
MISSING_PSEXEC = 4
ACCESS_DENIED = 5
UNSUPPORTED_RTA = 6
MISSING_REMOTE_HOST = 7

# Amount of seconds a command should take at a minimum.
# This can allow for arbitrary slow down of scripts
MIN_EXECUTION_TIME = 0

MAX_HOSTS = 64

# Useful constants
HKLM = "hklm"
HKCU = "hkcu"
HKU = "hku"
HKCR = "hkcr"

SZ = "sz"
EXPAND_SZ = "expand_sz"
MULTI_SZ = "multi_sz"
DWORD = "dword"


OS_MAPPING = {WINDOWS: [], MACOS: [], LINUX: []}


def requires_os(*os_list: str):
    if len(os_list) == 1 and isinstance(os_list[0], (list, tuple)):
        os_list = os_list[0]

    def decorator(f):
        # Register this function with the support os mapping
        for os_type in os_list:
            OS_MAPPING[os_type].append(f.__module__.split(".")[-1])

        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if CURRENT_OS not in os_list:
                # NOTE os.path.relpath supports Path objects and does not exist in pathlib
                filename = os.path.relpath(inspect.getsourcefile(f))
                func_name = f.__name__

                log(f"Unsupported OS for {filename}:{func_name}(). Expected {'/'.join(os_list)}", "!")
                return UNSUPPORTED_RTA
            return f(*args, **kwargs)

        return decorated

    return decorator


def check_dependencies(*paths: str) -> bool:
    missing = []
    for path in paths:
        if not Path(path).exists():
            log("Missing dependency %s" % path, "!")
            missing.append(path)
    return len(missing) == 0


def dependencies(*paths: str):
    missing = []
    for path in paths:
        if not Path(path).exists():
            missing.append(path)

    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if len(missing):
                log("Missing dependencies for %s:%s()" % (f.func_code.co_filename, f.func_code.co_name), "!")
                for dep in missing:
                    # NOTE os.path.relpath supports Path objects and does not exist in pathlib
                    print("    - %s" % os.path.relpath(dep, BASE_DIR))
                return MISSING_DEPENDENCIES
            return f(*args, **kwargs)

        return decorated

    return decorator


def pause():
    time.sleep(0.5)


def get_path(*path: str) -> str:
    return str(Path(BASE_DIR).joinpath(*path))


@contextlib.contextmanager
def temporary_file(contents, file_name=None):
    handle, close = temporary_file_helper(contents, file_name)

    try:
        yield handle
    finally:
        close()


def temporary_file_helper(contents, file_name=None):
    if not (file_name and Path(file_name).is_absolute()):
        file_name = Path(tempfile.gettempdir()) / file_name or f"temp{hash(contents):d}"

    with open(file_name, "wb" if isinstance(contents, bytes) else "w") as f:
        f.write(contents)

    f = open(file_name, "rb" if isinstance(contents, bytes) else "r")

    def close():
        f.close()
        os.remove(file_name)

    return f, close


def execute(
    command: Iterable,
    hide_log=False,
    mute=False,
    timeout: int = 30,
    wait=True,
    kill=False,
    drop=False,
    stdin: Optional[Union[bytes, str]] = None,
    shell=False,
    **kwargs,
):
    """Execute a process and get the output."""
    command_string = command
    close = None

    if isinstance(command, (list, tuple)):
        command_string = subprocess.list2cmdline(command)

        if shell:
            command = command_string
    else:
        sys.stderr.write("Deprecation warning! Switch arguments to a list for common.execute()\n\n")

    if not hide_log:
        print("%s @ %s > %s" % (USER_NAME, HOSTNAME, command_string))

    if isinstance(stdin, (bytes, str)):
        stdin, close = temporary_file_helper(stdin)

    stdout = subprocess.PIPE
    stderr = subprocess.STDOUT

    if drop or kill:
        devnull = open(os.devnull, "w")
        stdout = devnull
        stderr = devnull

    start = time.time()

    p = subprocess.Popen(command, stdin=stdin or subprocess.PIPE, stdout=stdout, stderr=stderr, shell=shell, **kwargs)

    if kill:
        delta = 0.5
        # Try waiting for the process to die
        for _ in range(int(timeout / delta) + 1):
            time.sleep(delta)
            if p.poll() is not None:
                return

        log("Killing process", str(p.pid))
        try:
            p.kill()
            time.sleep(0.5)
        except OSError:
            pass
    elif wait:
        output = ""

        if not stdin:
            try:
                p.stdin.write(os.linesep.encode("ascii"))
            except IOError:
                # this pipe randomly breaks when executing certain non-zero exit commands on linux
                pass

        while p.poll() is None:
            line = p.stdout.readline().decode("ascii", "ignore")
            if line:
                output += line
                if not (hide_log or mute):
                    print(line.rstrip())

        output += p.stdout.read().decode("ascii", "ignore")
        output = output.strip()

        # Add artificial sleep to slow down command lines
        end = time.time()
        run_time = end - start
        if run_time < MIN_EXECUTION_TIME:
            time.sleep(MIN_EXECUTION_TIME - run_time)

        if not (hide_log or mute):
            if p.returncode != 0:
                print("exit code = %d" % p.returncode)
            print("")

        if close:
            close()

        return p.returncode, output
    else:
        if close:
            close()

        return p


def log(message, log_type="+"):
    print("[%s] %s" % (log_type, message))


def copy_file(source, target):
    log("Copying %s -> %s" % (source, target))
    shutil.copy(source, target)


def create_macos_masquerade(masquerade: str):
    if platform.processor() == "arm":
        name = "com.apple.ditto_and_spawn_arm"
    else:
        name = "com.apple.ditto_and_spawn_intel"
    source = get_path("bin", name)

    copy_file(source, masquerade)


def link_file(source, target):
    log("Linking %s -> %s" % (source, target))
    execute(["ln", "-s", source, target])

def remove_file(path: str):
    if Path(path).is_file():
        log("Removing %s" % path, log_type="-")
        # Try three times to remove the file
        for _ in range(3):
            try:
                Path(path).unlink()
            except OSError:
                time.sleep(0.25)
            else:
                return


def remove_directory(path):
    if Path(path).is_dir():
        log(f"Removing directory {path:s}", log_type="-")
        shutil.rmtree(path)
    else:
        remove_file(path)


def is_64bit():
    return os.environ.get("PROCESSOR_ARCHITECTURE", "") in ("x64", "AMD64")


def remove_files(*paths):
    for path in paths:
        remove_file(path)


def clear_web_cache():
    log("Clearing temporary files", log_type="-")
    execute(["RunDll32.exe", "InetCpl.cpl,", "ClearMyTracksByProcess", "8"], hide_log=True)
    time.sleep(1)


def serve_web(ip=None, port=None, directory=BASE_DIR):
    handler = SimpleHTTPRequestHandler

    ip = ip or get_ip()

    if port is not None:
        server = HTTPServer((ip, port), handler)
    else:
        # Otherwise, try to find a port
        for port in range(8000, 9000):
            try:
                server = HTTPServer((ip, port), handler)
                break
            except socket.error:
                pass

    def server_thread():
        log(f"Starting web server on http://{ip}:{port:d} for directory {directory}")
        os.chdir(directory)
        server.serve_forever()

    # Start this thread in the background
    thread = threading.Thread(target=server_thread)
    thread.setDaemon(True)
    thread.start()

    time.sleep(0.5)
    return server, ip, port


def patch_file(source_file, old_bytes, new_bytes, target_file=None):
    target_file = target_file or target_file
    log(
        "Patching bytes %s [%s] --> %s [%s]"
        % (source_file, binascii.b2a_hex(old_bytes), target_file, binascii.b2a_hex(new_bytes))
    )

    with open(source_file, "rb") as f:
        contents = f.read()

    patched = contents.replace(old_bytes, new_bytes)

    with open(target_file, "wb") as f:
        f.write(patched)


def patch_regex(source_file, regex, new_bytes, target_file=None):
    regex = regex.encode("ascii")
    new_bytes = new_bytes.encode("ascii")
    target_file = target_file or source_file
    log("Patching by regex %s --> %s" % (source_file, target_file))

    with open(source_file, "rb") as f:
        contents = f.read()

    matches = re.findall(regex, contents)

    log("Changing %s -> %s" % (", ".join("{}".format(m) for m in matches), new_bytes))
    contents = re.sub(regex, new_bytes, contents)

    with open(target_file, "wb") as f:
        f.write(contents)


def wchar(s):
    return s.encode("utf-16le")


def find_remote_host():
    log("Searching for remote Windows hosts")
    _, stdout = execute("net view", hide_log=True)
    hosts = re.findall(r"\\\\([\w\d\._-]+)", stdout)

    # _, current_user = execute("whoami", hide_log=True)
    pending = {}

    log("Discovery %d possible hosts" % len(hosts))
    for name in hosts[:MAX_HOSTS]:
        name = name.lower()
        if name.split(".")[0] == HOSTNAME.split(".")[0]:
            continue

        # log("Checking if %s has remote admin permissions to %s" % (current_user, name))
        dev_null = open(os.devnull, "w")
        p = subprocess.Popen("sc.exe \\\\%s query" % name, stdout=dev_null, stderr=dev_null, stdin=subprocess.PIPE)
        pending[name] = p

    if len(pending) > 0:
        # See which ones return first with a success code, and use that host
        for _ in range(20):
            for hostname, pending_process in sorted(pending.items()):
                if pending_process.poll() is None:
                    pending_process.stdin.write(os.linesep)
                if pending_process.returncode == 0:
                    # Now need to get the IP address
                    ip = get_ipv4_address(hostname)
                    if ip is not None:
                        log("Using remote host %s (%s)" % (ip, hostname))
                        return ip
                    pending.pop(hostname)
            time.sleep(0.5)

    log("Unable to find a remote host to pivot to. Using local host %s" % HOSTNAME, log_type="!")
    return get_ip()


def get_ipv4_address(hostname):
    if re.match(IP_REGEX, hostname):
        return hostname

    code, output = execute(["ping", hostname, "-4", "-n", 1], hide_log=True)
    if code != 0:
        return None

    addresses = re.findall(IP_REGEX, output)
    if len(addresses) == 0:
        return None
    return addresses[0]


def find_writeable_directory(base_dir):
    for root, dirs, files in os.walk(base_dir):
        for d in dirs:
            subdir = Path(base_dir) / d
            try:
                test_file = Path(subdir) / "test_file"
                f = open(test_file, "w")
                f.close()
                os.remove(test_file)
                return subdir
            except IOError:
                pass


def check_system():
    return USER_NAME == "system" or USER_NAME.endswith("$")


PS_EXEC = get_path("bin", "PsExec.exe")


def run_system(arguments=None):
    if check_system():
        return None

    if arguments is None:
        # NOTE os.path.relpath supports Path objects and does not exist in pathlib
        arguments = [sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:]

    log("Attempting to elevate to SYSTEM using PsExec")
    if not Path(PS_EXEC).is_file():
        log("PsExec not found", log_type="-")
        return MISSING_PSEXEC

    p = subprocess.Popen([PS_EXEC, "-w", os.getcwd(), "-accepteula", "-s"] + arguments)
    p.wait()
    code = p.returncode
    if code == ACCESS_DENIED:
        log("Failed to escalate to SYSTEM", "!")
    return code


def write_reg(
    hive: str,
    key: str,
    value: str,
    data: Union[str, int],
    data_type: Union[str, int, list],
    restore=True,
    pause=False,
    append=False,
) -> None:
    with temporary_reg(hive, key, value, data, data_type, restore, pause, append):
        pass


def read_reg(hive: str, key: str, value: str) -> (str, str):
    winreg = get_winreg()

    if isinstance(hive, str):
        hives = {
            "hklm": winreg.HKEY_LOCAL_MACHINE,
            "hkcu": winreg.HKEY_LOCAL_MACHINE,
            "hku": winreg.HKEY_USERS,
            "hkcr": winreg.HKEY_CLASSES_ROOT,
        }
        hive = hives[hive.lower()]

    try:
        hkey = winreg.CreateKey(hive, key.rstrip("\\"))
        old_data, old_type = winreg.QueryValueEx(hkey, value)
    except WindowsError as e:
        # check if the key already exists
        if e.errno != 2:
            raise

        return None, None

    return old_data, old_type


@contextlib.contextmanager
def temporary_reg(
    hive: str,
    key: str,
    value: str,
    data: Union[str, int],
    data_type: Union[str, int, list] = "sz",
    restore=True,
    pause=False,
    append=False,
) -> None:
    winreg = get_winreg()

    if isinstance(hive, str):
        hives = {
            "hklm": winreg.HKEY_LOCAL_MACHINE,
            "hkcu": winreg.HKEY_CURRENT_USER,
            "hku": winreg.HKEY_USERS,
            "hkcr": winreg.HKEY_CLASSES_ROOT,
        }
        hive = hives[hive.lower()]

    if isinstance(data_type, str):
        attr = "REG_" + data_type.upper()
        data_type = getattr(winreg, attr)

    if data_type is None:
        data_type = winreg.REG_SZ

    key = key.rstrip("\\")
    hkey = winreg.CreateKey(hive, key)
    exists = False
    old_data = None
    old_type = None

    if hkey:
        try:
            old_data, old_type = winreg.QueryValueEx(hkey, value)
            exists = True
        except WindowsError as e:
            # check if the key already exists
            exists = False
            old_data, old_type = None, None
            if e.errno != 2:
                raise

    if append and exists:
        # If appending to the existing REG_MULTI_SZ key, then append to the end
        if not isinstance(data, list):
            data = [data]

        if isinstance(old_data, list):
            data = old_data + data

    data_string = ",".join(data) if isinstance(data, list) else data
    log("Writing to registry %s\\%s -> %s" % (key, value, data_string))
    winreg.SetValueEx(hkey, value, 0, data_type, data)
    stored, code = winreg.QueryValueEx(hkey, value)

    if data != stored:
        log("Wrote %s but retrieved %s" % (data, stored), log_type="-")

    # Allow code to execute within the context manager 'with'
    try:
        yield

    finally:
        if restore:
            time.sleep(0.5)

            if not exists:
                # If it didn't already exist, then delete it
                log("Deleting %s\\%s" % (key, value), log_type="-")
                winreg.DeleteValue(hkey, value)
            else:
                # Otherwise restore the value
                data_string = ",".join(old_data) if isinstance(old_data, list) else old_data
                log("Restoring registry %s\\%s -> %s" % (key, value, data_string), log_type="-")
                winreg.SetValueEx(hkey, value, 0, old_type, old_data)

        hkey.Close()
        print("")

        if pause:
            time.sleep(0.5)


def enable_logon_auditing(host="localhost", verbose=True, sleep=2):
    """Enable logon auditing on local or remote system to enable 4624 and 4625 events."""
    if verbose:
        log(f"Ensuring audit logging enabled on {host}")

    auditpol = "auditpol.exe /set /subcategory:Logon /failure:enable /success:enable"
    enable_logging = "Invoke-WmiMethod -ComputerName {} -Class Win32_process -Name create -ArgumentList '{}'".format(
        host, auditpol
    )
    command = ["powershell", "-c", enable_logging]
    enable = execute(command)

    # additional time to allow auditing to process
    time.sleep(sleep)
    return enable


def print_file(path):
    print(path)
    if not Path(path).is_file():
        print("--- NOT FOUND ----")
    else:
        print("-" * 16)
        with open(path, "r") as f:
            print(f.read().rstrip())

    print("")


# return pid by process.name
@requires_os('windows')
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
     print(f"[x] - Failed getting first process.")
     return

    while True:
        procname = pe32.szExeFile.decode("utf-8").lower()
        if pname.lower() in procname:
            CloseHandle(hProcessSnap)
            return pe32.th32ProcessID
        if not Process32Next(hProcessSnap, ctypes.byref(pe32)):
            CloseHandle(hProcessSnap)
            return None

@requires_os('windows')
def impersonate_system(): 
     try: 
        hp = win32api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, getppid("winlogon.exe"))
        th = win32security.OpenProcessToken(hp, TOKEN_DUPLICATE)
        new_tokenh = win32security.DuplicateTokenEx(th, 2, TOKEN_ALL_ACCESS , win32security.TokenImpersonation , win32security.SECURITY_ATTRIBUTES())
        win32security.ImpersonateLoggedOnUser(new_tokenh)
        print(f"[+] - Impersonated System Token via Winlogon")
        win32api.CloseHandle(hp)
     except Exception as e:
            print(f"[x] - Failed To Impersonate System Token via Winlogon")
            
@requires_os('windows')
def Inject(path, shellcode):
    import ctypes, time
    import ctypes.wintypes

    from ctypes.wintypes import BOOL
    from ctypes.wintypes import DWORD
    from ctypes.wintypes import HANDLE
    from ctypes.wintypes import LPVOID
    from ctypes.wintypes import LPCVOID
    import win32process
    # created suspended process
    info = win32process.CreateProcess(None, path, None, None, False, 0x04, None, None, win32process.STARTUPINFO())
    page_rwx_value = 0x40
    process_all = 0x1F0FFF
    memcommit = 0x00001000

    if info[0].handle > 0 :
       print(f"[+] - Created {path} Suspended")
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
    print(f'[+] - Allocated remote memory at {hex(lpBuffer)}')

    # write shellcode in allocated memory
    res = WriteProcessMemory(process_handle, lpBuffer, shellcode, shellcode_length, 0)
    if res > 0 :
        print('[+] - Shellcode written.')

    # create remote thread to start shellcode execution
    CreateRemoteThread(process_handle, None, 0, lpBuffer, 0, 0, 0)
    print('[+] - Shellcode Injection, done.')
