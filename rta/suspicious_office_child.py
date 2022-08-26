# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["windows"]
TRIGGERED_RULES = {
    "SIEM": [],
    "ENDPOINT": [
        {
            "rule_name": "Suspicious Microsoft Office Child Process",
            "rule_id": "c34a9dca-66cf-4283-944d-1800b28ae690",
        }
    ],
}
TACTICS = ["TA0001"]
RTA_ID = "c798f63a-f8be-459a-bb75-407e97f55faa"
EXE_FILE = common.get_path("bin", "renamed.exe")


@common.requires_os(PLATFORMS)
def main():
    binary = "winword.exe"
    common.copy_file(EXE_FILE, binary)

    # Execute command
    common.execute([binary, "/c", "certutil.exe"], timeout=5, kill=True)

    common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
