# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="08c90b80-538e-42ab-8986-342237f9740f",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {
            "rule_name": "Inhibit System Recovery via Untrusted Parent Process",
            "rule_id": "d3588fad-43ae-4f2d-badd-15a27df72132",
        },
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Inhibit System Recovery via Signed Binary Proxy",
            "rule_id": "740ad26d-3e67-47e1-aff1-adb47a697375",
        },
    ],
    siem=[],
    techniques=["T1218", "T1036", "T1216", "T1220", "T1490", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    cscript = "C:\\Users\\Public\\cscript.exe"
    common.copy_file(EXE_FILE, cscript)

    # Execute command
    common.log("Deleting Shadow Copies using Vssadmin spawned by cscript")
    common.execute([cscript, "/c", vssadmin, "delete", "shadows", "/For=C:"], timeout=10)
    common.remove_file(cscript)


if __name__ == "__main__":
    exit(main())
