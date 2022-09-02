# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="26339b1f-05ba-4fd8-94c2-8ee1613e4590",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Persistence via Login or Logout Hook", "rule_id": "5d0265bf-dea9-41a9-92ad-48a8dcd05080"}],
    techniques=["T1037"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/defaults"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake defaults command to mimic installing a login hook.")
    common.execute([masquerade, "write", "LoginHook"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
