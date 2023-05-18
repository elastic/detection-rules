# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="811ccfc2-d0fc-4a2a-85f6-6dc1235278bf",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Attempt to Disable Windows Defender Services",
            "rule_id": "32ab2977-2932-4172-9117-36e382591818",
        },
    ],
    siem=[],
    techniques=["T1562", "T1036"],
)


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    tempshell = "C:\\Users\\Public\\powershell.exe"
    common.copy_file(powershell, tempshell)

    # Execute command
    common.log("Attempting to stop Windefend, which will not work unless running as SYSTEM")
    common.execute([tempshell, "/c", "sc.exe stop Windefend"])
    common.remove_file(tempshell)


if __name__ == "__main__":
    exit(main())
