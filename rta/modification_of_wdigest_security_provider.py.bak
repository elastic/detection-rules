# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Modification of WDigest Security Provider
# RTA: modification_of_wdigest_security_provider.py
# ATT&CK: T1003
# Description: Sets WDigest\UseLogonCredential 1 temporarily

# TODO: Add context to what this does. Does it temporarily disable something?

import sys

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Modification of WDigest Security Provider")

    # TODO: See if common.temporory_reg should be used instead
    common.write_reg(common.HKLM,
                     "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", 1,
                     common.DWORD, restore=False, pause=True)

    common.write_reg(common.HKLM,
                     "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", 0,
                     common.DWORD, restore=False)


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
