# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="4a1e934b-0a92-4773-8d04-2092fcf47b48",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '5bb4a95d-5a08-48eb-80db-4c3a63ec78a8', 'rule_name': 'Suspicious PrintSpooler Service Executable File Creation'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    spoolsv = "C:\\Users\\Public\\spoolsv.exe"
    path = "C:\\Windows\\rta.exe"
    common.copy_file(EXE_FILE, spoolsv)

    common.execute([spoolsv, "/c", f"echo AAAAAAAA | Out-File {path}"], timeout=10, kill=True)
    common.remove_files(spoolsv, path)


if __name__ == "__main__":
    exit(main())
