# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a67586fd-cceb-4fb9-bf0e-d355b9e8921a",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "UAC Bypass via FodHelper Execution Hijack", "rule_id": "b5c0058e-2bca-4ed5-84b3-4e017c039c57"}
    ],
    siem=[],
    techniques=["T1548"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    key = "Software\\Classes\\ms-settings\\shell\\open\\command"
    value = "test"
    data = "test"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass

    fodhelper = "C:\\Users\\Public\\fodhelper.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, fodhelper)

    common.execute([fodhelper, "/c", powershell], timeout=2, kill=True)
    common.remove_file(fodhelper)


if __name__ == "__main__":
    exit(main())
