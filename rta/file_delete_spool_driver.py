# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="3a343699-374c-454a-841c-f0d0d4a3031f",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'c4818812-d44f-47be-aaef-4cfb2f9cc799', 'rule_name': 'Suspicious Print Spooler File Deletion'}],
    techniques=['T1068'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    file = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\rta.dll"
    common.copy_file(EXE_FILE, file)

    common.remove_files(file)


if __name__ == "__main__":
    exit(main())
