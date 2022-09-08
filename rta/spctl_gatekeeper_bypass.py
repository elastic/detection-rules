# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="cf71bf97-e3ba-474c-9b6b-538e5a8008b0",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Attempt to Disable Gatekeeper", "rule_id": "4da13d6e-904f-4636-81d8-6ab14b4e6ae9"}],
    techniques=["T1553"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/spctl"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Executing fake spctl for Gatekeeper defensive evasion.")
    common.execute([masquerade, "spctl", "--master-disable"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
