# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

from pathlib import Path

metadata = RtaMetadata(
    uuid="6df524fe-6a1a-417f-8f70-d6140ef739e2",
    platforms=["macos"],
    endpoint=[{"rule_name": "Persistence via a Hidden Plist Filename", "rule_id": "4090fed3-8ac4-45bf-8545-bae448fd38d4"}],
    siem=[{
        'rule_id': '092b068f-84ac-485d-8a55-7dd9e006715f',
        'rule_name': 'Creation of Hidden Launch Agent or Daemon'
    }],
    techniques=["T1547", "T1547.011", "T1543", "T1543.001", "T1564", "T1564.001"],
)


@common.requires_os(*metadata.platforms)
def main():

    plist_path = f"/Library/LaunchAgents/.test.plist"
    common.log(f"Executing hidden plist creation on {plist_path}")
    common.temporary_file_helper("testing", plist_path)


if __name__ == "__main__":
    exit(main())
