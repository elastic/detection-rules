# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a296162b-65c1-4fbe-ae34-67f606de408e",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '0564fb9d-90b9-4234-a411-82a546dc1343',
        'rule_name': 'Microsoft IIS Service Account Password Dumped'
    }],
    techniques=['T1003'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    appcmd = "C:\\Users\\Public\\appcmd.exe"
    common.copy_file(EXE_FILE, appcmd)

    # Execute command
    common.execute([appcmd, "/c", "echo", "/list", "/text&password"], timeout=10)
    common.remove_file(appcmd)


if __name__ == "__main__":
    exit(main())
