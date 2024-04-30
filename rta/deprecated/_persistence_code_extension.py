# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from .. import common
from .. import RtaMetadata


metadata = RtaMetadata(
    uuid="4ef86185-1a6e-4dd4-915c-d0f4281f68aa",
    platforms=["macos"],
    endpoint=[
        {
            "rule_id": "1f207515-b56f-4d15-929e-b6c0b1bb34f2",
            "rule_name": "Suspicious Manual VScode Extension Installation",
        }
    ],
    siem=[],
    techniques=["T1554"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/code"
    common.create_macos_masquerade(masquerade)

    common.log("Executing code commands to load fake extension.")
    common.execute([masquerade, "code", "--install-extension", "test"], timeout=10, kill=True)


if __name__ == "__main__":
    exit(main())
