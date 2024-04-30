# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b434626c-4787-4967-9984-50c0db12692f",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'd0e159cf-73e9-40d1-a9ed-077e3158a855', 'rule_name': 'Registry Persistence via AppInit DLL'}],
    techniques=['T1546', 'T1546.010'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    value = "AppInit_Dlls"
    data = "RTA"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
