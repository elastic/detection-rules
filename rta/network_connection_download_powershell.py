# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4b85db7b-b7e7-45d1-94de-210587e6d947",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '33f306e8-417c-411b-965c-c2812d6d3f4d', 'rule_name': 'Remote File Download via PowerShell'}],
    techniques=['T1105', 'T1059', 'T1059.001'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    fake_exe = "C:\\Users\\Public\\a.exe"

    # Execute command
    common.execute([powershell, "/c", f"Test-NetConnection -ComputerName google.com -Port 443 | Out-File {fake_exe}"],
                   timeout=10)
    common.remove_file(fake_exe)


if __name__ == "__main__":
    exit(main())
