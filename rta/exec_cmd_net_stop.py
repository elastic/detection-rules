# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="0427904d-1fba-40f4-a423-ea555d1a2335",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '035889c4-2686-4583-a7df-67f89c292f2c',
        'rule_name': 'High Number of Process and/or Service Terminations'
    }],
    techniques=['T1489'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    net = "C:\\Users\\Public\\net.exe"
    common.copy_file(EXE_FILE, net)

    # Execute command
    for i in range(0, 10):
        common.execute([net, "/c", "echo", "stop"], timeout=10)
    common.remove_file(net)


if __name__ == "__main__":
    exit(main())
