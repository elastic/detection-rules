# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Privilege Escalation via Port Monitor Registration
# RTA: port_monitor.py
# ATT&CK: T1013
# Description: Drops dummy DLL to Monitors registry path as non-system user, which would be executed with SYSTEM privs.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d7d1d0cf-a84a-4526-b0db-be59a210246e",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            "rule_id": "8f3e91c7-d791-4704-80a1-42c160d7aa27",
            "rule_name": "Potential Port Monitor or Print Processor Registration Abuse",
        }
    ],
    techniques=["T1547"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Writing registry key and dummy dll")

    key = "System\\CurrentControlSet\\Control\\Print\\Monitors\\blah"
    value = "test"
    dll = "test.dll"

    with common.temporary_reg(common.HKLM, key, value, dll):
        pass


if __name__ == "__main__":
    exit(main())
