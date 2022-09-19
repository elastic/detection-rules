# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Modification of WDigest Security Provider
# RTA: modification_of_wdigest_security_provider.py
# ATT&CK: T1003
# Description: Sets WDigest\UseLogonCredential 1 temporarily

# TODO: Add context to what this does. Does it temporarily disable something?

import sys

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c774ab90-d4d0-487b-b51e-928e7f3e9c48",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {"rule_id": "d703a5af-d5b0-43bd-8ddb-7a5d500b7da5", "rule_name": "Modification of WDigest Security Provider"}
    ],
    techniques=["T1003"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Modification of WDigest Security Provider")

    # TODO: See if common.temporory_reg should be used instead
    common.write_reg(
        common.HKLM,
        "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        "UseLogonCredential",
        1,
        common.DWORD,
        restore=False,
        pause=True,
    )

    common.write_reg(
        common.HKLM,
        "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        "UseLogonCredential",
        0,
        common.DWORD,
        restore=False,
    )


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
