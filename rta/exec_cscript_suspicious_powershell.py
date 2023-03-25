# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c562a05e-0ac8-46f9-91a2-5e99c8a1117c",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Suspicious PowerShell Execution via Windows Scripts",
            "rule_id": "3899dd3b-f31a-4634-8467-55326cd87597",
        },
    ],
    siem=[],
    techniques=["T1218", "T1036", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    cscript = "C:\\Users\\Public\\cscript.exe"
    common.copy_file(EXE_FILE, cscript)

    cmd = "powershell -c echo https://raw.githubusercontent.com/"
    # Execute command
    common.execute([cscript, "/c", cmd], timeout=10)
    common.remove_file(cscript)


if __name__ == "__main__":
    exit(main())
