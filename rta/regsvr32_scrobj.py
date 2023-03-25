# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="469c7bb5-44e2-4a85-b14d-5aee4f2b18c1",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Regsvr32 Scriptlet Execution", "rule_id": "0524c24c-e45e-4220-b21a-abdba0c46c4d"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {"rule_name": "Regsvr32 with Unusual Arguments", "rule_id": "5db08297-bf72-49f4-b426-f405c2b01326"},
    ],
    siem=[],
    techniques=["T1218", "T1036", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    regsvr32 = "C:\\Users\\Public\\regsvr32.exe"
    common.copy_file(EXE_FILE, regsvr32)

    common.execute([regsvr32, "/c", "echo", "scrobj.exe /i:"], timeout=10)
    common.remove_files(regsvr32)


if __name__ == "__main__":
    exit(main())
