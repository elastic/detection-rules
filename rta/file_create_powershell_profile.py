# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="1bc32d6d-c5c9-43c6-bada-6d26469b5dac",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '5cf6397e-eb91-4f31-8951-9f0eaa755a31', 'rule_name': 'Persistence via PowerShell profile'}],
    techniques=['T1546', 'T1546.013'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    path = "C:\\Users\\Public\\Documents\\WindowsPowerShell"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\profile.ps1"
    common.copy_file(EXE_FILE, file)

    common.remove_files(file)


if __name__ == "__main__":
    exit(main())
