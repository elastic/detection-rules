# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="ba802fb2-f183-420e-947b-da5ce0c74d123",
    platforms=["windows"],
    siem=[],
    endpoint=[{"rule_id": "ba802fb2-f183-420e-947b-da5ce0c74dd3", "rule_name": "Potential DLL SideLoad via a Microsoft Signed Binary"}],
    techniques=["T1574", "T1574.002"],
)

# iso contains WerFault.exe and a testing faultrep.dll to be sideloaded
ISO = common.get_path("bin", "werfault_iso.iso")
PROC = 'WER_RTA.exe'

# ps script to mount, execute a file and unmount ISO device
PS_SCRIPT = common.get_path("bin", "ExecFromISOFile.ps1")

@common.requires_os(*metadata.platforms)

def main():
    if Path(ISO).is_file() and Path(PS_SCRIPT).is_file():
        print(f'[+] - ISO File {ISO} will be mounted and executed via powershell')

        # import ExecFromISO function that takes two args -ISOFIle pointing to ISO file path and -procname pointing to the filename to execute
        command = f"powershell.exe -ExecutionPol Bypass -c import-module {PS_SCRIPT}; ExecFromISO -ISOFile {ISO} -procname {PROC};"
        common.execute(command)
        print(f'[+] - RTA Done!')

if __name__ == "__main__":
    exit(main())
