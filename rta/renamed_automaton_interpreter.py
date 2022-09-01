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
            "rule_name": "Renamed Windows Automaton Script Interpreter",
            "rule_id": "92d720dd-93b2-49e0-b68a-d5d6acbe4910",
        }
    ],
}
TECHNIQUES = ["T1036"]
RTA_ID = "8c128a2b-fa7b-4bfc-9ec9-934395460420"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(PLATFORMS)
def main():
    autohotkey = "C:\\Users\\Public\\notaut0hotkey.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, autohotkey)
    common.copy_file(RENAMER, rcedit)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute(
        [
            rcedit,
            autohotkey,
            "--set-version-string",
            "OriginalFilename",
            "AutoHotkey.exe",
        ]
    )

    common.execute([autohotkey], timeout=10, kill=True)

    common.remove_files(autohotkey, rcedit)


if __name__ == "__main__":
    exit(main())
