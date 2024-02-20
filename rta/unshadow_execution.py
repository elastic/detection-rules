# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c5cecd6d-a7c4-4e3b-970d-6ca5cfc5c662",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential Linux Credential Dumping via Unshadow",
            "rule_id": "05f95917-6942-4aab-a904-37c6db906503",
        }
    ],
    siem=[
        {
            "rule_name": "Potential Linux Credential Dumping via Unshadow",
            "rule_id": "e7cb3cfd-aaa3-4d7b-af18-23b89955062c"
        }
    ],
    techniques=["T1003", "T1003.008"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/unshadow"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake commands to dump credential via unshadow")
    common.execute([masquerade, "/etc/passwd /etc/shadow"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
