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
            "rule_name": "Execution from Unusual Directory",
            "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c",
        },
        {
            "rule_name": "Binary Masquerading via Untrusted Path",
            "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f",
        },
        {
            "rule_name": "Regsvr32 with Unusual Arguments",
            "rule_id": "5db08297-bf72-49f4-b426-f405c2b01326",
        },
    ],
}
TECHNIQUES = ["T1218", "T1036", "T1059"]
RTA_ID = "469d383a-d03f-470a-bcba-15da9dd373ed"
EXE_FILE = common.get_path("bin", "renamed.exe")


@common.requires_os(PLATFORMS)
def main():
    binary = "regsvr32.exe"
    common.copy_file(EXE_FILE, binary)

    # Execute Command
    common.execute([binary, "cd", "C:\\Users\\Public\\"], timeout=10, kill=True)

    common.remove_file(binary)


if __name__ == "__main__":
    exit(main())
