# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4d7ce5b3-f8e4-434c-9caa-c7e133146b27",
    platforms=["macos", "linux"],
    endpoint=[{"rule_name": "Empire Stager Execution", "rule_id": "b7974ff6-82ff-4743-9e07-1c6901b1f0ea"}],
    siem=[],
    techniques=["T1132", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
    else:
        common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake bash with base64 decode commands")
    common.execute(
        [masquerade, "exec(base64.b64decode*aW1wb3J0IHN5cztpbXBvcnQg)"],
        timeout=10,
        kill=True,
    )

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
