# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="71c81436-242d-4bc8-a195-93d1fdbc774b",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Suspicious Troubleshooting Pack Cabinet Execution",
            "rule_id": "d18721f0-dce0-4bbc-a56a-06ea511b025e",
        },
    ],
    siem=[],
    techniques=["T1218", "T1036"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    firefox = "C:\\Users\\Public\\firefox.exe"
    msdt = "C:\\Users\\Public\\msdt.exe"
    common.copy_file(EXE_FILE, firefox)
    common.copy_file(EXE_FILE, msdt)

    # Creating a high entropy file, and executing the rename operation
    common.execute(
        [firefox, "/c", "msdt.exe /c", "echo", "/cab", "C:\\Users\\Public\\"],
        timeout=10,
    )
    common.remove_files(firefox, msdt)


if __name__ == "__main__":
    exit(main())
