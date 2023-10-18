# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="fd86ee85-a3ee-4824-875b-bb386a23a578",
    platforms=["macos"],
    endpoint=[
        {
            "rule_id": "4dd92062-2871-43bc-adda-82f15cf6e189",
            "rule_name": "Decoded or Decrypted Payload Written to Suspicious Directory",
        }
    ],
    siem=[],
    techniques=["T1027", "T1140", "T1059", "T1059.004", "T1204", "T1204.002"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/openssl"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake openssl commands to decode payload")
    common.execute([masquerade, "-out", "/tmp/test", "enc", "-d"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
