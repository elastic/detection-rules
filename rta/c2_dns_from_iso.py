# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os

metadata = RtaMetadata(
    uuid="ba802fb2-f183-420e-947m-da5ce0235d123",
    platforms=["windows"],
    siem=[],
    endpoint=[{"rule_id": "3bc98de7-3349-43ac-869c-58357ae2aac0", "rule_name": "Suspicious DNS Query from Mounted Virtual Disk"}, 
              {"rule_id": "88f6c3d4-112e-4fad-b3ef-33095c954b63", "rule_name": "Suspicious DNS Query to Free SSL Certificate Domains"}, 
              {"rule_id": "d37ffe39-8e58-460f-938d-3bafbae60711", "rule_name": "DNS Query to Suspicious Top Level Domain"}],
    techniques=["T1071", "T1204", "T1071.004"],
)

# iso contains ping.exe to test for rules looking for suspicious DNS queries from mounted ISO file
ISO = common.get_path("bin", "ping_dns_from_iso.iso")
PROC = 'ping.exe'

# ps script to mount, execute a file and unmount ISO device
psf = common.get_path("bin", "ExecFromISOFile.ps1")

@common.requires_os(metadata.platforms)

def main():
    if os.path.exists(ISO) and os.path.exists(psf):
        print('[+] - ISO File ', ISO, 'will be mounted and executed via powershell')

        # 3 unique domains to trigger 3 unique rules looking for dns events via a process running from a mounted ISO file
        for domain in ["Abc.xyz", "content.dropboxapi.com", "x1.c.lencr.org"] :

            # import ExecFromISO function that takes two args -ISOFIle pointing to ISO file path and -procname pointing to the filename to execute and -cmdline for arguments
            command = "powershell.exe -ExecutionPol Bypass -c import-module " + psf + '; ExecFromISO -ISOFile ' + ISO + ' -procname '+ PROC + ' -cmdline ' + domain + ';'
            common.execute(command)

        print('[+] - RTA Done!')

if __name__ == "__main__":
    exit(main())
