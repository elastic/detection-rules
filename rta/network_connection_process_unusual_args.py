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
            "rule_name": "Binary Masquerading via Untrusted Path",
            "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f",
        },
        {
            "rule_name": "Network Connection via Process with Unusual Arguments",
            "rule_id": "95601d8b-b969-4189-9744-090140ae29e6",
        },
    ],
}
TACTICS = ["TA0005"]
RTA_ID = "8c77b44c-fb6d-4082-b62d-147918c622d9"
EXE_FILE = common.get_path("bin", "regsvr32.exe")


@common.requires_os(PLATFORMS)
def main():

    common.log("Making connection using fake regsvr32.exe")
    common.execute([EXE_FILE], timeout=10, kill=True)


if __name__ == "__main__":
    exit(main())
