# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

from pathlib import Path

metadata = RtaMetadata(
    uuid="7a8c8ab6-4994-47d1-b8b6-d1dca4499289",
    platforms=["macos"],
    endpoint=[
        {
            "rule_id": "eaf68cce-b250-4a17-a3c3-3c9c4cf1ec14",
            "rule_name": "Suspicious StartupItem Plist Creation or Modification",
        }
    ],
    siem=[],
    techniques=["T1037", "T1037.005"],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Executing creation on temp StartupParameters.plist file.")
    plist = "/Library/StartupItems/test/StartupParameters.plist"
    output_file = Path(plist)
    output_file.parent.mkdir(exist_ok=True, parents=True)
    common.temporary_file_helper("testing", file_name=str(plist))
    common.remove_directory("/Library/StartupItems/test/")


if __name__ == "__main__":
    exit(main())
