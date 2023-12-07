# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4ac771ca-5095-4a1b-ac6a-e2b714be8ccc",
    platforms=["windows"],
    endpoint=[{
        'rule_id': '377aad38-24e0-4dd7-93c2-bd231cb749e3',
        'rule_name': 'Unusual Startup Shell Folder Modification'
    }],
    siem=[],
    techniques=['T1547', 'T1547.001', 'T1112'],
)


@common.requires_os(*metadata.platforms)
def main():
    common.log("Temp Registry mod: Common Startup Folder")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    value = "Common Startup"
    data = "Test"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
