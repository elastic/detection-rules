# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="8fc20141-a73e-4c5e-9c9b-70acb69ab1dd",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Registry Persistence via Microsoft Office Descendant Process",
            "rule_id": "999e7a9a-334f-4b74-834f-a652f91531f2",
        }
    ],
    siem=[],
    techniques=["T1547", "T1112", "T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    posh = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, winword)
    common.copy_file(EXE_FILE, posh)

    cmd = (
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name Test -PropertyType String -value Testing"
    )
    rem_cmd = "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Test"

    # Execute command
    common.log("Fake ms word reg mod...")
    common.execute([winword, "/c", posh, "/c", cmd], timeout=10)
    common.execute([posh, "/c", rem_cmd], timeout=10)
    common.remove_file(winword)


if __name__ == "__main__":
    exit(main())
