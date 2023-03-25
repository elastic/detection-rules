# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7396debc-65ce-488f-845e-f92e68aceeb1",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {"rule_name": "UAC Bypass via Event Viewer", "rule_id": "ab29a79a-b3c2-4ae4-9670-70dd0ea68a4a"},
    ],
    siem=[],
    techniques=["T1548", "T1036"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    eventvwr = "C:\\Users\\Public\\eventvwr.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, eventvwr)

    common.execute([eventvwr, "/c", powershell], timeout=2, kill=True)
    common.remove_files(eventvwr)


if __name__ == "__main__":
    exit(main())
