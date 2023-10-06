# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1f1833da-dca4-467c-9a9d-a61cf41d6b63",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '770e0c4d-b998-41e5-a62e-c7901fd7f470', 'rule_name': 'Enumeration Command Spawned via WMIPrvSE'}],
    techniques=['T1047', 'T1018', 'T1087', 'T1518'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    wmiprvse = "C:\\Users\\Public\\wmiprvse.exe"
    arp = "C:\\Windows\\System32\\arp.exe"
    common.copy_file(EXE_FILE, wmiprvse)

    # Execute command
    common.execute([wmiprvse, "/c", arp], timeout=2, kill=True)
    common.remove_file(wmiprvse)


if __name__ == "__main__":
    exit(main())
