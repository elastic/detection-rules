# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Privilege Escalation via Port Monitor Registration
# RTA: port_monitor.py
# ATT&CK: T1013
# Description: Drops dummy DLL to Monitors registry path as non-system user, which would be executed with SYSTEM privs.

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": ["Potential Port Monitor or Print Processor Registration Abuse"],
    "ENDPOINT": []
}

@common.requires_os(PLATFORMS)
def main():
    common.log("Writing registry key and dummy dll")

    key = "System\\CurrentControlSet\\Control\\Print\\Monitors\\blah"
    value = "test"
    dll = "test.dll"

    with common.temporary_reg(common.HKLM, key, value, dll):
        pass


if __name__ == "__main__":
    exit(main())
