# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a3461218-f6c2-4178-ad85-f25b8df2d2e1",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Registry Run Key Modified by Unusual Process",
            "rule_id": "b2fcbb09-d9bd-4f6c-a08e-247548b4edcd",
        },
        {
            "rule_name": "Suspicious String Value Written to Registry Run Key",
            "rule_id": "727db78e-e1dd-4bc0-89b0-885cd99e069e",
        },
    ],
    siem=[],
    techniques=["T1547"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    posh = "C:\\Windows\\posh.exe"
    common.copy_file(EXE_FILE, posh)

    cmd = (
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name Test -PropertyType String -value rundll32"
    )
    rem_cmd = "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Test"

    # Execute command
    common.log("Fake ms word reg mod...")
    common.execute([posh, "/c", cmd], timeout=10)
    common.execute([posh, "/c", rem_cmd], timeout=10)
    common.remove_file(posh)


if __name__ == "__main__":
    exit(main())
