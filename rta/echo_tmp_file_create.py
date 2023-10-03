# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2182f7e5-fc4b-4476-86c3-e7128dfcaa7a",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Suspicious File Overwrite and Modification via Echo",
            "rule_id": "cd3a06dc-58c3-4d57-a03a-0d8991f237e7",
        }
    ],
    siem=[],
    techniques=["T1027", "T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    file_path = "/tmp/test"
    masquerade = "/tmp/testbin"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake bash commands to abnormal echo shell commands")
    command = f"bash -c 'echo* > {file_path}'"
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(file_path)


if __name__ == "__main__":
    exit(main())
