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
            "rule_name": "Windows Firewall Exception List Modified via Untrusted Process",
            "rule_id": "5c01669c-e1cc-4acc-95b6-8b5e4a92c970",
        }
    ],
}
TECHNIQUES = ["T1562"]
RTA_ID = "a0245bfc-d934-4b58-9a7c-a80eca05214b"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(PLATFORMS)
def main():
    posh = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, posh)

    cmd = "netsh addallowedprogramENABLE"
    # Execute command
    common.execute([posh, "/c", cmd], timeout=10)
    common.remove_file(posh)


if __name__ == "__main__":
    exit(main())
