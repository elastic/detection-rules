# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c9b68802-7d8b-4806-a817-ad50032efc58",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Execution via MSIEXEC", "rule_id": "9d1d6c77-8acc-478b-8a1f-43da8fa151c7"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
    ],
    siem=[],
    techniques=["T1218", "T1036"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    msiexec = "C:\\Users\\Public\\msiexec.exe"
    common.copy_file(EXE_FILE, msiexec)

    # Execute command
    common.execute([powershell, "/c", msiexec], timeout=10, kill=True)
    common.remove_file(msiexec)


if __name__ == "__main__":
    exit(main())
