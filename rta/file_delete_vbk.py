# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os


metadata = RtaMetadata(
    uuid="a6c80b08-ca72-4c3e-93c7-ac3421e4235e",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '11ea6bec-ebde-4d71-a8e9-784948f8e3e9',
        'rule_name': 'Third-party Backup Files Deleted via Unexpected Process'
    }],
    techniques=[""],
)


@common.requires_os(metadata.platforms)
def main():
    fakebkp = os.path.abspath("fake.vbk")
    with open(fakebkp, 'w'):
        pass
    common.remove_file(fakebkp)


if __name__ == "__main__":
    exit(main())
