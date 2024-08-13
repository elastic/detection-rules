# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="8a6aee3d-fa5f-41ca-83f6-d0669fc159ac",
    platforms=["macos"],
    endpoint=[],
    siem=[],
    techniques=[""],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Executing deletion on com.apple.loginwindow.test.plist file.")
    common.temporary_file_helper("testing", file_name="com.apple.loginwindow.test.plist")


if __name__ == "__main__":
    exit(main())
