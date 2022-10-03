# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="09936328-2aa9-4c4f-a9a7-a0ea7ab66fc0",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'fd7a6052-58fa-4397-93c3-4795249ccfa2', 'rule_name': 'Svchost spawning Cmd'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    svchost = "C:\\Users\\Public\\svchost.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    common.copy_file(EXE_FILE, svchost)

    # Execute command
    common.execute([svchost, "/c", cmd], timeout=2, kill=True)
    common.remove_file(svchost)


if __name__ == "__main__":
    exit(main())
