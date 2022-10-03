# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9df39b64-d856-48f1-abc2-fcb0b0da22bd",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '416697ae-e468-4093-a93d-59661fa619ec', 'rule_name': 'Control Panel Process with Unusual Arguments'}],
    techniques=[""],
)



@common.requires_os(metadata.platforms)
def main():
    control = "C:\\Windows\\System32\\control.exe"

    # Execute command
    common.execute([control, "a.jpg"], timeout=1)


if __name__ == "__main__":
    exit(main())
