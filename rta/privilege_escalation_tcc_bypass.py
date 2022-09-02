# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e45cd941-dee1-4275-8c63-2f8cab2cf8a6",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Potential Privilege Escalation via TCC bypass with fake TCC.db",
            "rule_id": "8446b30d-a9c4-4646-8261-979c06edd0ff",
        }
    ],
    siem=[],
    techniques=["T1068"],
)


@common.requires_os(metadata.platforms)
def main():

    common.log("Executing deletion on /tmp/TCC.db file.")
    common.temporary_file_helper("testing", file_name="/tmp/TCC.db")


if __name__ == "__main__":
    exit(main())
