# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="904cae88-f6bf-4585-b779-2451ce4b6b1b",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '0c7ca5c2-728d-4ad9-b1c5-bbba83ecb1f4',
        'rule_name': 'Peripheral Device Discovery'
    }],
    techniques=['T1120'],
)


@common.requires_os(*metadata.platforms)
def main():
    fsutil = "C:\\Windows\\System32\\fsutil.exe"

    # Execute command
    common.execute([fsutil, "fsinfo", "drives"], timeout=10)


if __name__ == "__main__":
    exit(main())
