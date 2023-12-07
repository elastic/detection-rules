# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="ec52377c-b2a8-4c44-8eb4-465376f2189a",
    platforms=["windows"],
    siem=[],
    endpoint=[
        {"rule_id": "33cdad6c-5809-4d78-94f0-5a5153289e7e", "rule_name": "Oversized DLL Creation followed by SideLoad"},
        {"rule_id": "65a402ff-904b-4d14-b7aa-fa0c5ae575f8", "rule_name": "Potential Evasion via Oversized Image Load"},
        {"rule_id": "b58a6662-cc72-4c1c-a24e-703427f3b725", "rule_name": "Rundll32 or Regsvr32 Executing an OverSized File"},
        {"rule_id": "d84090d7-91e4-4063-84c1-c1f410dd717b", "rule_name": "DLL Side Loading via a Copied Microsoft Executable"},
        {"rule_id": "901f0c30-a7c5-40a5-80e3-a50c6744632f", "rule_name": "RunDLL32/Regsvr32 Loads Dropped Executable"},
    ],
    techniques=["T1027", "T1574"],
)

# testing DLL that will spawn notepad once DllMain is invoked
DLL = common.get_path("bin", "faultrep.dll")

# we will copy WerFault.exe to temp to sideload our testing DLL faultrep.dll
WER = "c:\\windows\\system32\\werfault.exe"


@common.requires_os(*metadata.platforms)
def main():
    import os
    from os import path

    import win32file
    if Path(DLL).is_file():
        tempc = path.expandvars("%localappdata%\\Temp\\oversized.dll")
        rta_dll = path.expandvars("%localappdata%\\Temp\\faultrep.dll")
        rta_pe = path.expandvars("%localappdata%\\Temp\\wer.exe")
        # copy files to temp
        win32file.CopyFile(DLL,tempc, 0)
        win32file.CopyFile(WER, rta_pe, 0)
        if Path(tempc).is_file():
            print(f"[+] - {DLL} copied to {tempc}")
        print(f"[+] - File {tempc} will be appended with null bytes to reach 90MB in size.")
        # append null bytes to makde the DLL oversized 90+MB in size
        with open(tempc, 'rb+') as binfile:
            binfile.seek(100000000)
            binfile.write(b'\x00')

        # copied via cmd to trigger the rule - python is signed and won't trigger the file mod part of the rule
        common.execute(["cmd.exe", "/c", "copy", tempc, rta_dll])
        if Path(rta_dll).is_file() and Path(rta_pe).is_file():
            # should trigger rundll32 rules
            common.execute(["rundll32.exe", rta_dll, "DllMain"])
            # should trigger dll sideload from current dir
            common.execute(rta_pe)
        # cleanup
        common.execute(["taskkill", "/f", "/im", "notepad.exe"])
        print(f'[+] - Cleanup.')
        win32file.DeleteFile(tempc)
        win32file.DeleteFile(rta_dll)
        win32file.DeleteFile(rta_pe)
        print(f'[+] - RTA Done!')

if __name__ == "__main__":
    exit(main())
