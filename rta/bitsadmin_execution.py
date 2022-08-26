# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import subprocess
from pathlib import Path
from . import common


PLATFORMS = ["windows"]
TRIGGERED_RULES = {
    "SIEM": [],
    "ENDPOINT": [
        {
            "rule_name": "Suspicious Bitsadmin Activity",
            "rule_id": "676ac66c-4899-498f-ae21-ed5620af5477",
        },
        {
            "rule_name": "Suspicious Microsoft Office Child Process",
            "rule_id": "c34a9dca-66cf-4283-944d-1800b28ae690",
        },
    ],
}
TACTICS = ["TA0005", "TA0001"]
RTA_ID = "e7a55d39-37b4-4f37-9519-3779b3c23bfa"
ROOT_DIR = Path(__file__).parent
EXE_FILE = common.get_path("bin", "renamed.exe")


@common.requires_os(PLATFORMS)
def main():

    fake_word = ROOT_DIR / "winword.exe"
    common.log(f"Copying {EXE_FILE} to {fake_word}")
    common.copy_file(EXE_FILE, fake_word)

    command = subprocess.list2cmdline(["bitsadmin.exe", "/Transfer", "/Download"])
    common.execute([fake_word, "/c", command], timeout=15, kill=True)
    common.execute(["taskkill", "/f", "/im", "bitsadmin.exe"])

    common.remove_files(fake_word)


if __name__ == "__main__":
    exit(main())
