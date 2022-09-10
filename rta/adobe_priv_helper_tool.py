# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e5d376ae-d634-41fa-903c-42f35736a615",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Suspicious Child Process of Adobe Acrobat Reader Update Service",
            "rule_id": "f85ce03f-d8a8-4c83-acdc-5c8cd0592be7",
        }
    ],
    techniques=["T1068"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/com.adobe.ARMDC.SMJobBlessHelper"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake com.adobe.ARMDC.SMJobBlessHelper commands to adobe mimic privesc")
    common.execute([masquerade, "childprocess", masquerade], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
