# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Process Execution in System Restore
# RTA: system_restore_process.py
# ATT&CK: T1158
# Description: Copies mock malware into the System Volume Information directory and executes.

import os

from . import common

SYSTEM_RESTORE = "c:\\System Volume Information"


@common.requires_os(common.WINDOWS)
@common.dependencies(common.PS_EXEC)
def main():
    status = common.run_system()
    if status is not None:
        return status

    common.log("System Restore Process Evasion")
    program_path = common.get_path("bin", "myapp.exe")
    common.log("Finding a writeable directory in %s" % SYSTEM_RESTORE)
    target_directory = common.find_writeable_directory(SYSTEM_RESTORE)

    if not target_directory:
        common.log("No writeable directories in System Restore. Exiting...", "-")
        return common.UNSUPPORTED_RTA

    target_path = os.path.join(target_directory, "restore-process.exe")
    common.copy_file(program_path, target_path)
    common.execute(target_path)

    common.log("Cleanup", log_type="-")
    common.remove_file(target_path)


if __name__ == "__main__":
    exit(main())
