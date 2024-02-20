# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from .. import common
from .. import RtaMetadata

metadata = RtaMetadata(
    uuid="04361aca-0550-4134-ac21-939bf4a0582f",
    platforms=["macos", "linux"],
    endpoint=[
        {
            "rule_id": "41f1f818-0efe-4670-a2ed-7a4c200dd621",
            "rule_name": "Suspicious Content Extracted or Decompressed via Built-In Utilities",
        }
    ],
    siem=[],
    techniques=["T1059", "T1059.004", "T1027", "T1140"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
    else:
        common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake funzip commands to extract suspicious content")
    common.execute([masquerade, "tail", "-c", "funzip"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
