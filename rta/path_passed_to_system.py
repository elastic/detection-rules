# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7343a543-c2f6-4215-a21c-04eb8c764656",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Potential Masquerading as System Binary",
            "rule_id": "bb1de0c7-3504-4b31-8d3e-928aa3acf64f",
        }
    ],
    siem=[],
    techniques=["T1036", "T1036.004", "T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake bash commands to mimic passing a path to system bin")
    command = f"exec -a /System/Applications/test {masquerade}"
    common.execute([masquerade, "childprocess", command], timeout=5, kill=True, shell=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
