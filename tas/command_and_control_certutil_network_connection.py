# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="55437f9f-168c-4bb2-9cda-dacefd025ca9",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {'rule_id': '3838e0e3-1850-4850-a411-2e8c5ba40ba8', 'rule_name': 'Network Connection via Certutil'},
        {'rule_id': '66883649-f908-4a5b-a1e0-54090a1d3a32', 'rule_name': 'Connection to Commonly Abused Web Services'}
    ],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    certutil = "C:\\Users\\Public\\certutil.exe"
    common.copy_file(EXE_FILE, certutil)

    # Execute command
    common.execute([certutil, "/c", "Test-NetConnection -ComputerName drive.google.com -Port 443"], timeout=10)
    common.remove_file(certutil)


if __name__ == "__main__":
    exit(main())
