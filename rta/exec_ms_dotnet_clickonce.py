# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="23f0dde3-4803-4976-9a2a-5b5faca50b54",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Executable File Creation Followed by Immediate Network Connection",
            "rule_id": "8d11d741-7a06-41a1-a525-feaaa07ebbae",
        },
        {
            "rule_name": "Execution via Microsoft DotNet ClickOnce Host",
            "rule_id": "8606d5fe-5005-4f48-804a-3ad71a22e39d",
        },
    ],
    siem=[],
    techniques=["T1127", "T1218", "T1036", "T1204", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    dfsvc = "C:\\Users\\Public\\dfsvc.exe"
    common.copy_file(EXE_FILE, dfsvc)
    common.copy_file(EXE_FILE, rundll32)

    common.log("Loading mstscax.dll into posh")
    common.execute([rundll32, "-c", "echo dfshim1ShOpenVerbApplication"], timeout=10)
    common.execute(
        [
            dfsvc,
            "-c",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "443",
        ],
        timeout=10,
    )
    common.remove_files(dfsvc, rundll32)


if __name__ == "__main__":
    exit(main())
