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
            "rule_name": "Windows Command Shell Spawned via Microsoft Office",
            "rule_id": "2a396a3c-b343-42a9-b74b-c5b9925b6ee2",
        }
    ],
}
TECHNIQUES = ["T1566", "T1059"]
RTA_ID = "6c399694-d21c-4a19-9e58-8fa24eb399b9"
EXE_FILE = common.get_path("bin", "renamed.exe")


@common.requires_os(PLATFORMS)
def main():
    binary = "winword.exe"
    common.copy_file(EXE_FILE, binary)

    # Execute command
    common.execute([binary, "/c", "cmd.exe /c 'echo comspec'"], timeout=5, kill=True)

    common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
