# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d1988e82-a079-4fc2-99f7-2bdbc9af0e00",
    platforms=["macos"],
    endpoint=[{"rule_name": "Potential Persistence via Emond", "rule_id": "1cd247d8-00e8-4c62-b9ee-90cd1811460b"}],
    siem=[{"rule_name": "Suspicious Emond Child Process", "rule_id": "3e3d15c6-1509-479a-b125-21718372157e"}],
    techniques=["T1546"],
)


@common.requires_os(metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/emond"
    masquerade2 = "/tmp/bash"
    common.create_macos_masquerade(masquerade)
    common.create_macos_masquerade(masquerade2)

    # Execute commands
    common.log("Launching fake emond commands to mimic spawning child process.")
    common.execute([masquerade, "childprocess", masquerade2], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
