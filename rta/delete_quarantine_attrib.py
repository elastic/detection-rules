# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d7a67c3c-eadb-4bfb-beb1-61ddd86b4b83",
    platforms=["macos"],
    endpoint=[
        {
            "rule_id": "6e47b750-72c4-4af9-ad7b-0fc846df64d3",
            "rule_name": "Quarantine Attribute Deleted via Untrusted Binary",
        }
    ],
    siem=[],
    techniques=["T1553", "T1553.001"],
)


@common.requires_os(*metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/bash"
    masquerade2 = "/tmp/testbypass"
    common.create_macos_masquerade(masquerade)
    common.create_macos_masquerade(masquerade2)

    # Execute commands
    common.log("Launching fake delete commands to delete quarantine attribute.")
    command = f"{masquerade} xattr -d com.apple.quarantine"
    common.execute([masquerade2, "childprocess", command], shell=True, timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
