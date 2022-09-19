# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="31161e21-c290-4e51-a6d3-2865710793ff",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Potential Persistence via Periodic Tasks", "rule_id": "48ec9452-e1fd-4513-a376-10a1a26d2c83"}],
    techniques=["T1053"],
)


@common.requires_os(metadata.platforms)
def main():

    common.log("Executing file modification on periodic file test.conf to mimic periodic tasks creation")
    common.temporary_file_helper("testing", file_name="/private/etc/periodic/test.conf")


if __name__ == "__main__":
    exit(main())
