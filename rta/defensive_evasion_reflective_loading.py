# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [],
    "ENDPOINT": [
        {
            "rule_name": "MacOS Monterey Reflective Code Loading",
            "rule_id": "16fba7a9-f8f6-43ce-ae24-6a392a48e49c",
        }
    ],
}
TACTICS = ["TA0002", "TA0005"]
RTA_ID = "b023cf4b-2856-4170-9ea0-884041904159"


@common.requires_os(PLATFORMS)
def main():

    common.log(
        "Executing deletion on /private/tmp/NSCreateObjectFileImageFromMemory-test file."
    )
    common.temporary_file_helper(
        "testing", file_name="/private/tmp/NSCreateObjectFileImageFromMemory-test"
    )


if __name__ == "__main__":
    exit(main())
