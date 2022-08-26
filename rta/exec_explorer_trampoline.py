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
            "rule_name": "Execution of Commonly Abused Utilities via Explorer Trampoline",
            "rule_id": "5e8498bb-8cc0-412f-9017-793d94ab76a5",
        }
    ],
}
TACTICS = ["TA0002", "TA0005", "TA0001"]
RTA_ID = "5e911636-6f68-40d3-b1ef-7a951a397cc9"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(PLATFORMS)
def main():
    explorer = "C:\\Users\\Public\\explorer.exe"
    common.copy_file(EXE_FILE, explorer)

    common.execute(
        [
            explorer,
            "-c",
            "echo",
            "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}",
            ";mshta",
        ],
        timeout=10,
    )
    common.remove_files(explorer)


if __name__ == "__main__":
    exit(main())
