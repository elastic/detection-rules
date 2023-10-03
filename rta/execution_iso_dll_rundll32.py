# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="8bd17f51-3fc0-46a8-9e1a-662723314ad4",
    platforms=["windows"],
    siem=[],
    endpoint=[{"rule_id": "779b9502-7912-4773-95a1-51cd702a71c8", "rule_name": "Suspicious ImageLoad from an ISO Mounted Device"}, 
              {"rule_id": "08fba401-b76f-4c7b-9a88-4f3b17fe00c1", "rule_name": "DLL Loaded from an Archive File"}],
    techniques=["T1574", "T1574.002"],
)

# iso contains shortcut to start Rundll32 to load a testing DLL that when executed it will spawn notepad.exe
ISO = common.get_path("bin", "lnk_from_iso_rundll.iso")
# shortcut name
PROC = 'Invite.lnk'

# ps script to mount, execute a file and unmount ISO device
PS_SCRIPT = common.get_path("bin", "ExecFromISOFile.ps1")

@common.requires_os(*metadata.platforms)

def main():
    if Path(ISO).is_file() and Path(PS_SCRIPT).is_file():
        print(f'[+] - ISO File {ISO} will be mounted and executed via powershell')

        # import ExecFromISO function that takes two args -ISOFIle pointing to ISO file path and -procname pointing to the filename to execute
        command = f"powershell.exe -ExecutionPol Bypass -c import-module {PS_SCRIPT}; ExecFromISO -ISOFile {ISO} -procname {PROC};"
        common.execute(command)

        # terminate notepad.exe spawned as a result of the DLL execution
        common.execute(["taskkill", "/f", "/im", "notepad.exe"])
        print(f'[+] - RTA Done!')

if __name__ == "__main__":
    exit(main())
