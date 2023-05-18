# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ff744c89-20cb-4be0-9725-2430d0be7f6a",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Persistence via DirectoryService Plugin Modification",
            "rule_id": "89fa6cb7-6b53-4de2-b604-648488841ab8",
        }
    ],
    techniques=["T1547"],
)


@common.requires_os(metadata.platforms)
def main():

    common.log("Executing file modification on test.dsplug to mimic DirectoryService plugin modification")
    common.temporary_file_helper("testing", file_name="/Library/DirectoryServices/PlugIns/test.dsplug")


if __name__ == "__main__":
    exit(main())
