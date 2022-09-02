# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="370c3432-65f5-4068-b879-916bc1297c60",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Enumeration of Users or Groups via Built-in Commands",
            "rule_id": "6e9b351e-a531-4bdc-b73e-7034d6eed7ff",
        }
    ],
    techniques=["T1069", "T1087"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/ldapsearch"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake ldapsearch commands to mimic user or group enumeration")
    common.execute([masquerade, "testing"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
