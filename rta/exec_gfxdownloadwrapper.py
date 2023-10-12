# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e7f3a729-e5ee-462b-ba1c-dd778468d24d",
    platforms=["windows"],
    endpoint=[
        {
            'rule_id': 'aafe3c78-15d9-4853-a602-663b8fada5b5',
            'rule_name': 'Potential Evasion via Intel GfxDownloadWrapper'
        }
    ],
    siem=[],
    techniques=['T1218', 'T1105'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    gfx = "C:\\Users\\Public\\GfxDownloadWrapper.exe"
    common.copy_file(EXE_FILE, gfx)

    common.execute([gfx, "/c", "echo", "run", "0", "http"], timeout=5, kill=True)
    common.remove_files(gfx)


if __name__ == "__main__":
    exit(main())
