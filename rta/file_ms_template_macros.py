# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os

metadata = RtaMetadata(
    uuid="858475a2-78a6-40f8-8691-7ce0c631cc0c",
    platforms=["windows"],
    endpoint=[{
        'rule_id': '608eae71-6797-4ded-bfaa-41bcb17a8498',
        'rule_name': 'Office Application Startup via Template File Modification'
    }],
    siem=[],
    techniques=['T1137', 'T1137.001'],
)


@common.requires_os(metadata.platforms)
def main():
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Templates\\"
    os.makedirs(path, exist_ok=True)
    file = path + "\\Normal.dotm"

    common.temporary_file_helper("testing", file_name=file)


if __name__ == "__main__":
    exit(main())
