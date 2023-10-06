# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="00402735-f78d-4ed6-9f8e-a1b365c42f5b",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '97aba1ef-6034-4bd3-8c1a-1e0996b27afa', 'rule_name': 'Suspicious Zoom Child Process'}],
    techniques=['T1036', 'T1055'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    zoom = "C:\\Users\\Public\\zoom.exe"
    pwsh = "C:\\Users\\Public\\pwsh.exe"
    common.copy_file(EXE_FILE, zoom)
    common.copy_file(EXE_FILE, pwsh)

    # Execute command
    common.execute([zoom, "/c", pwsh], timeout=2, kill=True)
    common.remove_files(zoom, pwsh)


if __name__ == "__main__":
    exit(main())
