# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Emond Rules Creation or Modification",
            "rule_id": "a6bf4dd4-743e-4da8-8c03-3ebd753a6c90",
        }
    ],
    "ENDPOINT": [],
}
TACTICS = []
RTA_ID = "2c186f11-d07c-4df6-8b86-bf9ffd6ca871"


@common.requires_os(PLATFORMS)
def main():

    common.log(
        "Executing file modification on test.plist to mimic emond file modification"
    )
    common.temporary_file_helper(
        "testing", file_name="/private/etc/emond.d/rules/test.plist"
    )


if __name__ == "__main__":
    exit(main())
