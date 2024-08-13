# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4ef86185-1a6e-4dd4-915c-d0f4281f68aa",
    platforms=["macos"],
    endpoint=[],
    siem=[],
    techniques=[""],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Executing code commands to load fake extension.")
    common.execute(["code", "--install-extension", "test"])


if __name__ == "__main__":
    exit(main())
