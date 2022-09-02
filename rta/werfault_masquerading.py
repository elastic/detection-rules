# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="41c82553-01c2-41d6-a15d-3499fa99b4c0",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Windows Error Manager/Reporting Masquerading", "rule_id": "3d16f5f9-da4c-4b15-a501-505761b75ca6"}
    ],
    siem=[],
    techniques=["T1055", "T1036"],
)

EXE_FILE = common.get_path("bin", "regsvr32.exe")


@common.requires_os(metadata.platforms)
def main():
    werfault = "C:\\Users\\Public\\werfault.exe"

    common.copy_file(EXE_FILE, werfault)
    common.log("Making connection using fake werfault.exe")
    common.execute([werfault], timeout=10, kill=True)
    common.remove_file(werfault)


if __name__ == "__main__":
    exit(main())
