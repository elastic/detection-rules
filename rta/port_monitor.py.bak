# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Privilege Escalation via Port Monitor Registration
# RTA: port_monitor.py
# ATT&CK: T1013
# Description: Drops dummy DLL to Monitors registry path as non-system user, which would be executed with SYSTEM privs.

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Writing registry key and dummy dll")

    key = "System\\CurrentControlSet\\Control\\Print\\Monitors\\blah"
    value = "test"
    dll = "test.dll"

    with common.temporary_reg(common.HKLM, key, value, dll):
        pass


if __name__ == "__main__":
    exit(main())
