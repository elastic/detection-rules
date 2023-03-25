# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="0885b643-a199-4453-95e0-be0d1f29aafc",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Execution from MSSQL Service", "rule_id": "547636af-cad2-4be0-a74e-613c7bb86664"}
    ],
    siem=[],
    techniques=["T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    sqlserver = "C:\\Users\\Public\\sqlserver.exe"
    common.copy_file(EXE_FILE, sqlserver)

    # Execute command
    common.execute([sqlserver, "/c", powershell], timeout=10, kill=True)
    common.remove_file(sqlserver)


if __name__ == "__main__":
    exit(main())
