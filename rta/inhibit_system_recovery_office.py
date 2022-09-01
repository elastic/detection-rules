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
            "rule_name": "Inhibit System Recovery via Untrusted Parent Process",
            "rule_id": "d3588fad-43ae-4f2d-badd-15a27df72132",
        },
        {
            "rule_name": "Inhibit System Recovery via Microsoft Office Process",
            "rule_id": "58a08390-e69d-4b32-9487-1d1ddb16ba09",
        },
    ],
}
TECHNIQUES = ["T1490", "T1047", "T1566"]
RTA_ID = "aa05a870-7075-42f9-a009-49aa75ea99fa"
EXE_FILE = common.get_path("bin", "renamed.exe")


@common.requires_os(PLATFORMS)
def main():
    binary = "winword.exe"
    common.copy_file(EXE_FILE, binary)

    # Execute command
    common.log("Deleting shadow copies using vssadmin")
    common.execute(
        [binary, "/c", "vssadmin.exe", "delete", "shadows", "/all", "/quiet"],
        timeout=5,
        kill=True,
    )

    common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
