# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ffb8fca8-7aa3-4c40-8122-46516b0d9c9a",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '871ea072-1b71-4def-b016-6278b505138d', 'rule_name': 'Enumeration of Administrator Accounts'}],
    techniques=[""],
)


@common.requires_os(metadata.platforms)
def main():
    wmic = "C:\\Windows\\System32\\wbem\\WMIC.exe"

    # Execute command
    common.execute([wmic, "useraccount", "get", "name"], timeout=10)


if __name__ == "__main__":
    exit(main())
