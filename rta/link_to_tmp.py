# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="eb5834cf-fcd8-4318-a656-5315a664e61d",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Link Creation to Temp Directory", "rule_id": "ccca5e9f-2625-4b95-9b15-d5d8fc56df2c"},
    ],
    siem=[],
    techniques=["T1222", "T1222.002"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/ln"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake ln commands to link to temp directory")
    with common.temporary_file("testing", "/tmp/test.txt"):
        common.execute([masquerade, "-s", "/tmp/test.txt"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
