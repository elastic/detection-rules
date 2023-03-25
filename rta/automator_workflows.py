# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6294e8bd-a82e-4d60-9de7-cceb639e91d9",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Suspicious Automator Workflows Execution", "rule_id": "e390d36d-c739-43ee-9e3d-5a76fa853bd5"}
    ],
    siem=[{"rule_name": "Suspicious Automator Workflows Execution", "rule_id": "5d9f8cfc-0d03-443e-a167-2b0597ce0965"}],
    techniques=["T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/automator"
    masquerade2 = "/tmp/com.apple.automator.runner"
    common.create_macos_masquerade(masquerade)
    common.copy_file("/usr/bin/curl", masquerade2)

    # Execute command
    common.log("Launching fake commands to launch Automator workflows")
    common.execute([masquerade], timeout=10, kill=True)
    common.execute([masquerade2, "portquiz.net"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
