# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="84a9bc41-8b2e-434e-b6ae-237e9202c745",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'ebf1adea-ccf2-4943-8b96-7ab11ca173a5', 'rule_name': 'IIS HTTP Logging Disabled'}],
    techniques=['T1562', 'T1562.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    appcmd = "C:\\Users\\Public\\appcmd.exe"
    common.copy_file(EXE_FILE, appcmd)

    # Execute command
    common.execute([appcmd, "/c", "echo", "/dontLog:True"], timeout=10)
    common.remove_file(appcmd)


if __name__ == "__main__":
    exit(main())
