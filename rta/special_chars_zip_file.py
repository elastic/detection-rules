# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="dce9cb95-b97d-4874-ab7a-26382a1ba348",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {"rule_name": "Potential Microsoft Office Sandbox Evasion", "rule_id": "d22a85c6-d2ad-4cc4-bf7b-54787473669a"}
    ],
    techniques=["T1497"],
)


@common.requires_os(metadata.platforms)
def main():

    common.log("Creating suspicious zip file with special characters to mimic evasion of sanboxed office apps.")
    common.temporary_file_helper("testing", file_name="/tmp/~$test.zip")


if __name__ == "__main__":
    exit(main())
