# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

from pathlib import Path

metadata = RtaMetadata(
    uuid="c01971a7-3aa6-4c43-aee6-85d48e93b8c1",
    platforms=["macos"],
    endpoint=[],
    siem=[],
    techniques=[""],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Executing plutil commands to modify plist file.")
    plist = f"{Path.home()}/Library/Preferences/com.apple.Terminal.plist"
    common.execute(["plutil", "-convert", "xml1", plist])
    common.execute(["plutil", "-convert", "binary1", plist])


if __name__ == "__main__":
    exit(main())
