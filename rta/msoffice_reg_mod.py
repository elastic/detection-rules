# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="61abdbb3-bcab-4c57-8b5d-2a5c9226e580",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Registry Modification via Microsoft Office", "rule_id": "926b6cd1-c0c7-46d4-82d6-9deb6ae431d6"}
    ],
    siem=[],
    techniques=["T1547", "T1112", "T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    common.copy_file(EXE_FILE, winword)

    cmd = (
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name Test -PropertyType String -value Testing"
    )
    rem_cmd = "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Test"

    # Execute command
    common.log("Fake ms word reg mod...")
    common.execute([winword, "/c", cmd], timeout=10)
    common.execute([winword, "/c", rem_cmd], timeout=10)
    common.remove_file(winword)


if __name__ == "__main__":
    exit(main())
