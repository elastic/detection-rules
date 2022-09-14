# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="3c8fc2cc-fa66-4c91-ae72-c72accaa92b7",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Potential Persistence via Login Hook", "rule_id": "ac412404-57a5-476f-858f-4e8fbb4f48d8"}],
    techniques=["T1547"],
)


@common.requires_os(metadata.platforms)
def main():

    common.log("Executing deletion on /tmp/com.apple.loginwindow.plist file.")
    common.temporary_file_helper("testing", file_name="/tmp/com.apple.loginwindow.plist")


if __name__ == "__main__":
    exit(main())
