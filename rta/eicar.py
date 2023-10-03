# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="c8efd8c9-b32c-482a-90ff-f2d366a2af45",
    platforms=["macos", "linux", "windows"],
    endpoint=[{"rule_id": "c4539c79-9f55-4b36-b06f-8aff82563bca", "rule_name": "Behavior Protection - EICAR"}],
    siem=[],
    techniques=["TA0002"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    if common.CURRENT_OS in ["linux", "macos"]:
        if common.CURRENT_OS == "linux":
            source = common.get_path("bin", "linux.ditto_and_spawn")
            common.copy_file(source, masquerade)
        else:
            common.create_macos_masquerade(masquerade)

        # Execute command
        common.log("Launching behavior diag test")
        common.execute([masquerade, "elastic-behavior-protection-eicar"], timeout=10, kill=True)

        # cleanup
        common.remove_file(masquerade)
    else:

        cmd = "C:\\Windows\\System32\\cmd.exe"

        # Execute command
        common.log("Launching eicar test")
        common.execute([cmd, "/c", "echo", "elastic-behavior-protection-eicar"])


if __name__ == "__main__":
    exit(main())
