# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c0f3618b-a7d9-403c-8b42-572da0b20f47",
    platforms=["macos"],
    endpoint=[{"rule_name": "Shlayer Malware Infection", "rule_id": "3dda1ac2-86ef-41f5-ad3b-d9396383e104"}],
    siem=[],
    techniques=["T1105"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/curl"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake curl command to download Shlayer payloads")
    common.execute([masquerade, "-f0L"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
