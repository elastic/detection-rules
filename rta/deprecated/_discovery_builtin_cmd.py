# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from .. import common
from .. import RtaMetadata


metadata = RtaMetadata(
    uuid="b4454817-eea7-458d-8426-e4f529352e39",
    platforms=["macos"],
    endpoint=[
        {"rule_id": "92525741-9ca8-466e-acee-ceb14ab0dc34", "rule_name": "System Discovery via Built-In Utilities"}
    ],
    siem=[],
    techniques=["T1082", "T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake commands for system discovery with builtin cmds")
    common.execute([masquerade, "testhdiutil test", "test perltest -test"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
