# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="672cd0e6-fa5a-468f-80c8-04f92bead469",
    platforms=["windows"],
    endpoint=[{"rule_name": "BCDEdit Safe Mode Command Execution", "rule_id": "6d660b32-23bf-434b-a588-1cdc91224664"}],
    siem=[],
    techniques=["T1490", "T1218", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed.exe")


def main():
    binary = "winword.exe"
    common.copy_file(EXE_FILE, binary)
    bcdedit = "bcdedit.exe"

    # Messing with the boot configuration is not a great idea so create a backup:
    common.log("Exporting the boot configuration....")
    backup_file = os.path.abspath("boot.cfg")
    common.execute([bcdedit, "/export", backup_file])

    # WARNING: this sets up computer to boot into Safe Mode upon reboot
    common.log("Changing boot configuration", log_type="!")
    common.execute([binary, "/c", bcdedit, "/set", "{default}", "safeboot", "minimal"])

    # Delete value to not boot into Safe Mode
    common.log("Reset boot configuration", log_type="!")
    common.execute([binary, "/c", bcdedit, "/deletevalue", "safeboot"])

    # Restore the boot configuration
    common.log("Restoring boot configuration from %s" % backup_file, log_type="-")
    common.execute([bcdedit, "/import", backup_file])

    common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
