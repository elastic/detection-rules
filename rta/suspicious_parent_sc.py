# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="eb1ecbae-a7d0-4beb-89fe-fbf2db0edce3",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'e8571d5f-bea1-46c2-9f56-998de2d3ed95',
        'rule_name': 'Service Control Spawned via Script Interpreter'
    }],
    techniques=['T1021'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    sc = "C:\\Users\\Public\\sc.exe"
    common.copy_file(EXE_FILE, sc)

    common.execute([powershell, "/c", sc, "echo", "create"], timeout=5, kill=True)
    common.remove_files(sc)


if __name__ == "__main__":
    exit(main())
