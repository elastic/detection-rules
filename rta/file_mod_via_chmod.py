# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="dbbfda7f-376d-482d-b7ea-3bb1e8918584",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "File Made Executable by Suspicious Parent Process",
            "rule_id": "42ab2c0f-b10d-467d-8c6d-def890cf3f68",
        }
    ],
    siem=[],
    techniques=["T1222", "T1222.002", "T1564"],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Executing chmod on tmp files.")
    with common.temporary_file("testing", "/tmp/test.txt"):
        common.execute(["chmod", "+x", "/tmp/test.txt"])


if __name__ == "__main__":
    exit(main())
