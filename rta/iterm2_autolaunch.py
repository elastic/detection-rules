# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
from pathlib import Path


metadata = RtaMetadata(
    uuid="9010739f-05c5-4fc0-b806-27753d3d6b5b",
    platforms=["macos"],
    endpoint=[],
    siem=[],
    techniques=[""],
)


@common.requires_os(*metadata.platforms)
def main():

    iterm2 = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
    backup_iterm2 = "/tmp/backup_iterm2"
    masquerade_bash = "/tmp/bash"
    path = Path(iterm2)
    restore_backup = False

    if path.is_file():
        restore_backup = True
        common.copy_file(iterm2, backup_iterm2)

    common.create_macos_masquerade(iterm2)
    common.create_macos_masquerade(masquerade_bash)

    # Execute command
    common.log("Spawning bash from fake iterm2 commands")
    command = f"{masquerade_bash} /Users/test/.config/iterm2/AppSupport/Scripts/test"
    common.execute([iterm2, "childprocess", command], timeout=10, kill=True)

    # reset iterm2 and cleanup
    if restore_backup:
        common.copy_file(backup_iterm2, iterm2)

    common.remove_file(backup_iterm2)
    common.remove_file(masquerade_bash)


if __name__ == "__main__":
    exit(main())
