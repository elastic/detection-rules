# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6df14bf3-6153-4ff2-aa0f-f91f2aa06b7b",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Potential Masquerading as SVCHOST", "rule_id": "5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c"
        },
    ],
    siem=[{'rule_id': '5d1d6907-0747-4d5d-9b24-e4a18853dc0a', 'rule_name': 'Suspicious Execution via Scheduled Task'}],
    techniques=['T1053', 'T1053.005', 'T1036', 'T1036.004'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    svchost = "C:\\Users\\Public\\svchost.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, svchost)

    common.execute([svchost, "/c", "echo", "schedule", f";{powershell}", "C:\\Users\\A"], timeout=5, kill=True)
    common.remove_files(svchost)


if __name__ == "__main__":
    exit(main())
