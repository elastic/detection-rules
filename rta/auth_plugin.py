# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="96c3cc10-7f86-428c-b353-e9de52472a96",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Authorization Plugin Modification", "rule_id": "e6c98d38-633d-4b3e-9387-42112cd5ac10"}],
    techniques=["T1547"],
)


@common.requires_os(metadata.platforms)
def main():

    common.log("Executing file modification on test.plist to mimic authorization plugin modification")
    common.temporary_file_helper("testing", file_name="/Library/Security/SecurityAgentPlugins/test.plist")


if __name__ == "__main__":
    exit(main())
