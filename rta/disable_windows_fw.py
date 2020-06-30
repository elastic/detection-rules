# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Disable Windows Firewall
# RTA: disable_windows_fw.py
# ATT&CK: T1089
# Description: Uses netsh.exe to backup, disable and restore firewall rules.

import os

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("NetSH Advanced Firewall Configuration", log_type="~")
    netsh = "netsh.exe"

    rules_file = os.path.abspath("fw.rules")

    # Check to be sure that fw.rules does not already exist from previously running this script
    common.remove_file(rules_file)

    common.log("Backing up rules")
    common.execute([netsh, "advfirewall", "export", rules_file])

    common.log("Disabling the firewall")
    common.execute([netsh, "advfirewall", "set", "allprofiles", "state", "off"])

    common.log("Undoing the firewall change", log_type="-")
    common.execute([netsh, "advfirewall", "import", rules_file])

    common.remove_file(rules_file)


if __name__ == "__main__":
    exit(main())
