# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ea187b1f-4aa0-4ffc-bac9-9ee1d55552fd",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Access of Stored Browser Credentials", "rule_id": "20457e4f-d1de-4b92-ae69-142e27a4342a"}],
    techniques=["T1539", "T1555"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake commands to aquire browser creds")
    cookie_path = f"{Path.home()}/Library/Application Support/Google/Chrome/Default/Cookies"
    common.execute([masquerade, cookie_path], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
