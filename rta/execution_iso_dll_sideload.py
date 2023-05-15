# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os

metadata = RtaMetadata(
    uuid="ba802fb2-f183-420e-947b-da5ce0c74d123",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "ba802fb2-f183-420e-947b-da5ce0c74dd3", "rule_name": "Potential DLL SideLoad via a Microsoft Signed Binary"}],
    techniques=["T1574"],
)

# iso contains WerFault.exe and a testing faultrep.dll to be sideloaded
ISO = common.get_path("bin", "rta_iso.iso")

# ps script to mount, execute WerFault.exe and unmount ISO device
psf = common.get_path("bin", "mount_wer_iso.ps1")

@common.requires_os(metadata.platforms)

def main():
    if os.path.exists(ISO) and os.path.exists(psf):
        print('[+] - ISO File ', ISO, 'will be mounted and executed via powershell')
        command = "powershell.exe -ExecutionPol Bypass " + psf
        common.execute(command)
        print('[+] - RTA Done!')

if __name__ == "__main__":
    exit(main())
