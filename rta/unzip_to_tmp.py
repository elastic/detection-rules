# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="de7e28b2-c01d-4cd7-abb7-ddb64bce5f45",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Compressed File Extracted to Temp Directory", "rule_id": "24fa0f80-7e3a-4b27-801a-30ef53f190bf"}
    ],
    siem=[],
    techniques=["T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/Users/bash"
    common.create_macos_masquerade(masquerade)

    command = 'bash -c "unzip * /tmp/* -d *"'

    common.log("Executing unzip to tmp directory.")
    common.execute([masquerade, "childprocess", command], shell=True, timeout=5, kill=True)


if __name__ == "__main__":
    exit(main())
