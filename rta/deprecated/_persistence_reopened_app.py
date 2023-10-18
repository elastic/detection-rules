# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from .. import common
from .. import RtaMetadata


metadata = RtaMetadata(
    uuid="8a6aee3d-fa5f-41ca-83f6-d0669fc159ac",
    platforms=["macos"],
    endpoint=[{"rule_id": "57e9e13a-4eda-4b5f-b39a-d38c8104ab0f", "rule_name": "Re-Opened Application Persistence"}],
    siem=[],
    techniques=["T1547", "T1547.007"],
)


@common.requires_os(*metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/bash"
    common.create_macos_masquerade(masquerade)

    path = Path(f"{Path.home()}/Library/Preferences/ByHost/")
    path.mkdir(exist_ok=True, parents=True)
    plist = path / "com.apple.loginwindow.plist"

    common.log("Executing file modification on com.apple.loginwindow.test.plist file.")
    common.execute([masquerade, "childprocess", f"echo 'test'> {plist}"], timeout=5, kill=True)

    # cleanup
    common.remove_directory(str(path))


if __name__ == "__main__":
    exit(main())
