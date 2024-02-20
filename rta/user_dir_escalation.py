# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SYSTEM Escalation from User Directory
# RTA: user_dir_escalation.py
# ATT&CK: T1044
# Description: Spawns mock malware written to a regular user directory and executes as System.

import os
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="dc734786-66bd-4be6-bd06-eb41fa7b6745",
    platforms=["windows"],
    endpoint=[],
    siem=[],
    techniques=[]
)


@common.requires_os(*metadata.platforms)
@common.dependencies(common.PS_EXEC)
def main():
    # make sure path is absolute for psexec
    status = common.run_system()
    if status is not None:
        return status

    common.log("Run a user-writeable file as system")
    source_path = common.get_path("bin", "myapp.exe")

    target_directory = "c:\\users\\fake_user_rta-%d" % os.getpid()
    if not Path(target_directory).is_dir():
        Path(target_directory).mkdir(parents=True)

    target_path = Path(target_directory) / "user_file.exe"
    common.copy_file(source_path, target_path)
    common.execute([target_path])

    common.remove_directory(target_directory)


if __name__ == "__main__":
    exit(main())
