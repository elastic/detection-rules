# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="aef45f58-14c8-4934-8518-62a254d96b77",
    platforms=["linux"],
    endpoint=[],
    siem=[],
    techniques=["T1036", "T1036.004"]
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/apt"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake builtin commands for Linux Binary Masquerading via Untrusted Path")
    command = "install"
    common.execute([masquerade, command], timeout=10, kill=True, shell=True)
    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
