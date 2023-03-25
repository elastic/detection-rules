# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b30811a1-f734-4c28-b386-bcf43b214e09",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Execution via Outlook Application COM Object",
            "rule_id": "17030515-5ed0-43c8-9602-f97cbebd43c0",
        },
        {"rule_name": "Potential Masquerading as SVCHOST", "rule_id": "5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c"},
    ],
    siem=[],
    techniques=["T1566", "T1218", "T1036", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    outlook = "C:\\Users\\Public\\outlook.exe"
    svchost = "C:\\Users\\Public\\svchost.exe"
    common.copy_file(EXE_FILE, outlook)
    common.copy_file(EXE_FILE, svchost)

    common.log("Fake outlook spawning powershell")
    common.execute([svchost, "/c", outlook, "/c", "powershell -Embedding"], timeout=10, kill=True)

    common.remove_files(outlook, svchost)


if __name__ == "__main__":
    exit(main())
