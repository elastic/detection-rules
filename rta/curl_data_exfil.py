# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="aec658cc-a5df-42e8-8e09-810b484b9ef2",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "MacOS Potential Data Exfiltration via Curl",
            "rule_id": "192ec591-1d00-4c16-a717-8a7481038d23",
        }
    ],
    siem=[],
    techniques=["T1048"],
)


@common.requires_os(*metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/curl"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake curl commands to simulate data exfil")
    common.execute([masquerade, "-F", "*@*.zip", "http*"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
