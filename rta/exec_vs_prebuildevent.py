# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c4445d28-fe0f-4822-b0b0-92e188a9ca0e",
    platforms=["windows"],
    endpoint=[{
        'rule_id': '74be6307-2d15-4c71-8072-fc606f337a51',
        'rule_name': 'Execution via MS VisualStudio Pre/Post Build Events'
    }],
    siem=[],
    techniques=['T1127', 'T1127.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    cmd = "C:\\Users\\Public\\cmd.exe"
    common.copy_file(EXE_FILE, cmd)
    common.copy_file(EXE_FILE, msbuild)

    common.execute([msbuild, "/c", cmd, "/c", cmd, "echo C:\\Users\\A\\AppData\\Local\\Temp\\tmpa.exec.cmd"],
                   timeout=10, kill=True)
    common.remove_files(cmd, msbuild)


if __name__ == "__main__":
    exit(main())
