# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="99d89d71-4025-481d-80f9-efb795beca29",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "UAC Bypass via Malicious MMC Snap-In Execution",
            "rule_id": "ccdf56a8-697b-497c-ab90-3aa01bfc5f9f",
        },
    ],
    siem=[],
    techniques=["T1548", "T1036"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    mmc = "C:\\Users\\Public\\mmc.exe"
    msc = "C:\\Users\\Public\\a.msc"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, mmc)
    common.copy_file(EXE_FILE, msc)

    common.execute([mmc, "/c", "echo", "a.msc b.msc"], timeout=2, kill=True)
    common.execute([mmc, "/c", powershell], timeout=2, kill=True)
    common.remove_files(mmc, msc)


if __name__ == "__main__":
    exit(main())
