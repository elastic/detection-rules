# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f2e5c332-ad54-4bfa-8d51-ce1a85e749d7",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '12f07955-1674-44f7-86b5-c35da0a6f41a', 'rule_name': 'Suspicious Cmd Execution via WMI'}],
    techniques=['T1047'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    wmiprvse = "C:\\Users\\Public\\wmiprvse.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    common.copy_file(EXE_FILE, wmiprvse)

    # Execute command
    common.execute([wmiprvse, "/c", cmd, "/c", "echo", "\\\\127.0.0.1\\", "'1>'"], timeout=5)
    common.remove_file(wmiprvse)


if __name__ == "__main__":
    exit(main())
