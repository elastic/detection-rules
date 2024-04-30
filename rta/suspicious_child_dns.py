# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9f58f9e7-a0f5-48e6-a924-d437fd626195",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {'rule_id': '8c37dc0e-e3ac-4c97-8aa0-cf6a9122de45', 'rule_name': 'Unusual Child Process of dns.exe'},
        {'rule_id': 'c7ce36c0-32ff-4f9a-bfc2-dcb242bf99f9', 'rule_name': 'Unusual File Modification by dns.exe'}
    ],
    techniques=['T1133'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    dns = "C:\\Users\\Public\\dns.exe"
    common.copy_file(EXE_FILE, dns)

    common.execute([dns, "/c", EXE_FILE, "echo AAAAAA | Out-File a.txt"], timeout=5, kill=True)
    common.remove_files(dns)


if __name__ == "__main__":
    exit(main())
