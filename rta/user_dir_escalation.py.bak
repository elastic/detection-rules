# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: SYSTEM Escalation from User Directory
# RTA: user_dir_escalation.py
# ATT&CK: T1044
# Description: Spawns mock malware written to a regular user directory and executes as System.

import os

from . import common


@common.requires_os(common.WINDOWS)
@common.dependencies(common.PS_EXEC)
def main():
    # make sure path is absolute for psexec
    status = common.run_system()
    if status is not None:
        return status

    common.log("Run a user-writeable file as system")
    source_path = common.get_path("bin", "myapp.exe")

    target_directory = "c:\\users\\fake_user_rta-%d" % os.getpid()
    if not os.path.exists(target_directory):
        os.makedirs(target_directory)

    target_path = os.path.join(target_directory, "user_file.exe")
    common.copy_file(source_path, target_path)
    common.execute([target_path])

    common.remove_directory(target_directory)


if __name__ == "__main__":
    exit(main())
