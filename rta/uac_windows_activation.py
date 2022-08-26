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
            "rule_name": "UAC Bypass via Windows Activation Execution Hijack",
            "rule_id": "71ad1420-ed83-46d0-835b-63d4b2008427",
        }
    ],
}
TACTICS = ["TA0004"]
RTA_ID = "9643aa7f-fe2e-46f1-b3ef-8cf07b5aaaa0"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(PLATFORMS)
def main():
    key = "Software\\Classes\\Launcher.SystemSettings\\shell\\open\\command"
    value = "test"
    data = "test"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass

    changepk = "C:\\Users\\Public\\changepk.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, changepk)

    common.execute([changepk, "/c", powershell], timeout=2, kill=True)
    common.remove_file(changepk)


if __name__ == "__main__":
    exit(main())
