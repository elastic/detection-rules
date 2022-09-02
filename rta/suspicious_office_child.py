# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c798f63a-f8be-459a-bb75-407e97f55faa",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Microsoft Office Child Process", "rule_id": "c34a9dca-66cf-4283-944d-1800b28ae690"}
    ],
    siem=[],
    techniques=["T1566"],
)

EXE_FILE = common.get_path("bin", "renamed.exe")


@common.requires_os(metadata.platforms)
def main():
    binary = "winword.exe"
    common.copy_file(EXE_FILE, binary)

    # Execute command
    common.execute([binary, "/c", "certutil.exe"], timeout=5, kill=True)

    common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
