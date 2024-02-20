# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="631a211d-bdaa-4b9d-a786-31d84d7bc070",
    platforms=["linux", "macos"],
    endpoint=[
        {"rule_id": "31da6564-b3d3-4fc8-9a96-75ad0b364363", "rule_name": "Tampering of Bash Command-Line History"}
    ],
    siem=[],
    techniques=["T1070", "T1070.003"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/history"

    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
    else:
        common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake builtin commands for tampering of bash command line history")
    command = "-c"
    common.execute([masquerade, command], timeout=10, kill=True, shell=True)
    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
