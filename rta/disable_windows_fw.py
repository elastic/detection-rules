# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Disable Windows Firewall
# RTA: disable_windows_fw.py
# ATT&CK: T1089
# signal.rule.name: Disable Windows Firewall Rules via Netsh
# Description: Uses netsh.exe to backup, disable and restore firewall rules.

import os

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="75e14e5a-1188-47ea-9b96-2cf6e9443fc2",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "4b438734-3793-4fda-bd42-ceeada0be8f9", "rule_name": "Disable Windows Firewall Rules via Netsh"}],
    techniques=["T1562"],
)


@common.requires_os(metadata.platforms)
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
