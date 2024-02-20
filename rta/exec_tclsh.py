# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9332cece-38b7-49e1-9f8d-e879913ffdfb",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Tclsh execution followed by immediate network connection",
            "rule_id": "ac1eaed8-2aee-48d7-9824-2be1f00eda0e",
        }
    ],
    siem=[],
    techniques=["T1059"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/tclsh"
    common.copy_file("/usr/bin/curl", masquerade)

    common.log("Executing commands to mimic network activity from tclsh")
    common.execute([masquerade, url], shell=True)


if __name__ == "__main__":
    exit(main())
