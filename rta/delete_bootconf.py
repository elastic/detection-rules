# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Boot Config Deletion With bcdedit
# RTA: delete_bootconf.py
# ATT&CK: T1107
# signal.rule.name: Modification of Boot Configuration
# Description: Uses bcdedit.exe to backup the current boot configuration, and then to delete the current boot
#  configuration, finally restoring the original.

import os

from . import common


@common.requires_os(common.WINDOWS)
def main():
    # Messing with the boot configuration is probably not a great idea so create a backup:
    common.log("Exporting the boot configuration....")
    bcdedit = "bcdedit.exe"
    backup_file = os.path.abspath("boot.cfg")
    common.execute(["bcdedit.exe", "/export", backup_file])

    # WARNING: this is a destructive command which might be super bad to run
    common.log("Changing boot configuration", log_type="!")
    common.execute([bcdedit, "/set", "{current}", "bootstatuspolicy", "ignoreallfailures"])
    common.execute([bcdedit, "/set", "{current}", "recoveryenabled", "no"])

    # Restore the boot configuration
    common.log("Restoring boot configuration from %s" % backup_file, log_type="-")
    common.execute([bcdedit, "/import", backup_file])


if __name__ == "__main__":
    exit(main())
