# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

from pathlib import Path

metadata = RtaMetadata(
    uuid="a9754fdb-2beb-454a-b918-36a56c5bf7bd",
    platforms=["macos"],
    endpoint=[
        {
            "rule_id": "482e5ab2-029c-4896-afc0-f3e6b8280920",
            "rule_name": "Suspicious Apple Mail Rule Creation or Modification",
        }
    ],
    siem=[],
    techniques=[""],
)


@common.requires_os(metadata.platforms)
def main():

    common.log("Executing deletion on SyncedRules.plist file.")
    plist = f"{Path.home()}/Library/Mobile Documents/com.apple.mail/Data/test/MailData/SyncedRules.plist"
    output_file = Path(plist)
    output_file.parent.mkdir(exist_ok=True, parents=True)
    common.temporary_file_helper("testing", file_name=str(plist))
    common.remove_directory(f"{Path.home()}/Library/Mobile Documents/com.apple.mail/Data/test/")


if __name__ == "__main__":
    exit(main())
