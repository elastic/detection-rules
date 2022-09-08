# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e8612e97-2df7-4e85-94ee-e61bc58c6479",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "UAC Bypass via WSReset Execution Hijack", "rule_id": "11c67af9-9599-4800-9e84-bd38f2a51581"}
    ],
    siem=[],
    techniques=["T1548"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    key = "Software"
    value = "ms-windows-store"
    data = "test"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass

    wsreset = "C:\\Users\\Public\\wsreset.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, wsreset)

    common.execute([wsreset, "/c", powershell], timeout=2, kill=True)
    common.remove_file(wsreset)


if __name__ == "__main__":
    exit(main())
