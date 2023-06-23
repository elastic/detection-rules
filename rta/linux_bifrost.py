# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="88118ccc-0d0c-49f7-9ca2-408946d89ed4",
    platforms=["linux"],
    endpoint=[
        {"rule_name": "Potential Linux Attack via Bifrost", "rule_id": "2b067b3c-1e32-493d-9cb5-ce0a176b5793"}
    ],
    siem=[],
    techniques=["T1558", "T1550"],
)


@common.requires_os(metadata.platforms)
def main():

    print("I am a linux bifrost rule")


if __name__ == "__main__":
    exit(main())
