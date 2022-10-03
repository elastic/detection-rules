# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1c5acd8d-f356-4b18-aaf5-4b66064d18e4",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'be8afaed-4bcd-4e0a-b5f9-5562003dde81', 'rule_name': 'Searching for Saved Credentials via VaultCmd'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    vaultcmd = "C:\\Users\\Public\\vaultcmd.exe"
    common.copy_file(EXE_FILE, vaultcmd)

    # Execute command
    common.execute([vaultcmd, "/c", "echo", "/list"], timeout=10)
    common.remove_file(vaultcmd)


if __name__ == "__main__":
    exit(main())
