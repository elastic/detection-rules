# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f0340de4-e433-49a3-ba8c-de0ded32840d",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '4ed493fc-d637-4a36-80ff-ac84937e5461',
        'rule_name': 'Execution via MSSQL xp_cmdshell Stored Procedure'
    }],
    techniques=['T1059'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    sqlservr = "C:\\Users\\Public\\sqlservr.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    common.copy_file(EXE_FILE, sqlservr)

    # Execute command
    common.execute([sqlservr, "/c", cmd], timeout=2, kill=True)
    common.remove_file(sqlservr)


if __name__ == "__main__":
    exit(main())
