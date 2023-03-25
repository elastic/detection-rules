# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b084e9dd-0c79-480c-b488-049ab8167b38",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {"rule_name": "Potential Hidden Local User Account Creation", "rule_id": "41b638a1-8ab6-4f8e-86d9-466317ef2db5"}
    ],
    techniques=["T1078"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/dscl"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake dscl commands to mimic creating a local hidden account.")
    common.execute([masquerade, "IsHidden", "create", "true"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
