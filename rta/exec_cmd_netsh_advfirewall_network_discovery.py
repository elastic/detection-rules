# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="5b52f7e5-e2bc-4a2d-82bd-2e844c081519",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '8b4f0816-6a65-4630-86a6-c21c179c0d09', 'rule_name': 'Enable Host Network Discovery via Netsh'}],
    techniques=['T1562', 'T1562.004'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    netsh = "C:\\Users\\Public\\netsh.exe"
    common.copy_file(EXE_FILE, netsh)

    # Execute command
    common.execute([netsh, "/c", "echo", "advfirewall", "group=Network Discovery", "enable=Yes"], timeout=2)
    common.remove_file(netsh)


if __name__ == "__main__":
    exit(main())
