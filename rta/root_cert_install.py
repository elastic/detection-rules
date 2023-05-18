# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="633313a4-dbe5-420f-b4ae-90c481a7f881",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Attempt to Install Root Certificate", "rule_id": "bc1eeacf-2972-434f-b782-3a532b100d67"}],
    techniques=["T1553"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/security"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Executing fake security commands to add a root cert.")
    common.execute([masquerade, "add-trusted-cert"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
