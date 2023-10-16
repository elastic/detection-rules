# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a56d07b3-c459-4a72-adab-b93bbe008f0f",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Non-Native Dylib Extracted into New Directory",
            "rule_id": "62cc9cf4-5440-4237-aa5b-ea8db83deb3d",
        }
    ],
    siem=[],
    techniques=["T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    # Execute command"
    common.log("Launching commands to tar tmp dir.")
    common.execute(["mkdir"], timeout=10, kill=True)

    with common.temporary_file("testing", "/tmp/test.txt"):
        common.execute(["tar", "-cf", "test.dylib", "/tmp/test.txt"], timeout=10, kill=True)

    # cleanup
    common.remove_file("test.dylib")


if __name__ == "__main__":
    exit(main())
