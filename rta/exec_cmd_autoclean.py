# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f04a9c39-215b-42a7-9f81-3f72d76c8c72",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '1dcc51f6-ba26-49e7-9ef4-2655abb2361e',
        'rule_name': 'UAC Bypass via DiskCleanup Scheduled Task Hijack'
    }],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\proc.exe"
    common.copy_file(EXE_FILE, proc)

    common.execute([proc, "/c", "echo", "/autoclean", "/d"], timeout=5, kill=True)
    common.remove_files(proc)


if __name__ == "__main__":
    exit(main())
