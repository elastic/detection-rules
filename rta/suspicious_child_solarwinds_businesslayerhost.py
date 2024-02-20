# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e55c13d4-ab70-4a3d-ba1e-c54156000e42",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '93b22c0a-06a0-4131-b830-b10d5e166ff4', 'rule_name': 'Suspicious SolarWinds Child Process'}],
    techniques=['T1106', 'T1195', 'T1195.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    buzz = "C:\\Users\\Public\\SolarWinds.BusinessLayerHost.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, buzz)

    # Execute command
    common.execute([buzz, "/c", powershell], timeout=2, kill=True)
    common.remove_file(buzz)


if __name__ == "__main__":
    exit(main())
