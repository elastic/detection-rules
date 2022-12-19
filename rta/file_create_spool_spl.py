# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os

metadata = RtaMetadata(
    uuid="d7e708b5-11fe-4340-a105-a4d0c8c1e13d",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'a7ccae7b-9d2c-44b2-a061-98e5946971fa',
        'rule_name': 'Suspicious Print Spooler SPL File Created'
    }],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    file = "C:\\Windows\\System32\\spool\\PRINTERS\\rta.spl"
    common.copy_file(EXE_FILE, file)

    common.remove_files(file)


if __name__ == "__main__":
    exit(main())
