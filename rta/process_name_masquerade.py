# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os

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
            "rule_name": "Potential Masquerading as SVCHOST",
            "rule_id": "5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c",
        },
        {
            "rule_name": "Execution via Renamed Signed Binary Proxy",
            "rule_id": "b0207677-5041-470b-981d-13ab956cf5b4",
        },
    ],
}
TACTICS = ["TA0005"]
RTA_ID = "98adf0ff-2d8e-4eea-8d68-42084204bb74"
CMD_PATH = "c:\\windows\\system32\\cmd.exe"


@common.requires_os(PLATFORMS)
def main():
    masquerades = ["svchost.exe", "lsass.exe"]

    for name in masquerades:
        path = os.path.abspath(name)
        common.copy_file(CMD_PATH, path)
        common.execute(path, timeout=3, kill=True)
        common.remove_file(path)


if __name__ == "__main__":
    exit(main())
