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
            "rule_name": "External IP Address Discovery via Untrusted Program",
            "rule_id": "dfe28e03-9b0b-47f5-9753-65ed2666663f",
        }
    ],
}
TACTICS = ["TA0007"]
RTA_ID = "5e1ca4f9-16cc-4dd3-bfba-4bd5c7579f4a"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(PLATFORMS)
def main():
    posh = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, posh)

    # Execute command
    common.log("Retrieving the public IP Address using ipify")
    common.execute(
        [posh, "/c", "iwr", "http://api.ipify.org/", "-UseBasicParsing"], timeout=10
    )
    common.remove_file(posh)


if __name__ == "__main__":
    exit(main())
