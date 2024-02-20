# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="bc837b89-713a-4d21-a086-8649e8411f11",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '9a5b4e31-6cde-4295-9ff7-6be1b8567e1b', 'rule_name': 'Suspicious Explorer Child Process'}],
    techniques=['T1566', 'T1566.001', 'T1566.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    explorer = "C:\\Users\\Public\\explorer.exe"
    common.copy_file(EXE_FILE, explorer)

    common.execute([explorer, "-c", "echo", "-Embedding", ";powershell"], timeout=5, kill=True)
    common.remove_file(explorer)


if __name__ == "__main__":
    exit(main())
