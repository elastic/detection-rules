# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ad9c9b24-cff3-4c4e-9fba-5c51ca9e58ae",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Control Panel Process with Unusual Arguments", "rule_id": "a4862afb-1292-4f65-a15f-8d6a8019b5e2"}
    ],
    siem=[],
    techniques=["T1218"],
)


@common.requires_os(metadata.platforms)
def main():

    # Execute command
    common.log("Executing control.exe with a non-existing .cpl file")
    common.execute(["control.exe", "cpl1.cpl:../a"], timeout=10)


if __name__ == "__main__":
    exit(main())
