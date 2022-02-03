# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Enable RDP Through Registry
# RTA: registry_rdp_enable.py
# signal.rule.name: Potential Modification of Accessibility Binaries
# ATT&CK: T1076
# Description: Identifies registry write modification to enable RDP access.

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Enabling RDP Through Registry")

    # get the current value
    key = "System\\CurrentControlSet\\Control\\Terminal Server"
    value = "fDenyTSConnections"

    with common.temporary_reg(common.HKLM, key, value, 1, common.DWORD):
        # while temporarily disabled, re-enable the service
        common.write_reg(common.HKLM, key, value, 0, common.DWORD, restore=False)


if __name__ == "__main__":
    exit(main())
