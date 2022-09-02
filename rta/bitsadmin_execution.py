# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import subprocess
from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e7a55d39-37b4-4f37-9519-3779b3c23bfa",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Bitsadmin Activity", "rule_id": "676ac66c-4899-498f-ae21-ed5620af5477"},
        {"rule_name": "Suspicious Microsoft Office Child Process", "rule_id": "c34a9dca-66cf-4283-944d-1800b28ae690"},
    ],
    siem=[],
    techniques=["T1197", "T1566"],
)

ROOT_DIR = Path(__file__).parent
EXE_FILE = common.get_path("bin", "renamed.exe")


@common.requires_os(metadata.platforms)
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
