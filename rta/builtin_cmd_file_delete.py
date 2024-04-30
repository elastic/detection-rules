# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
from . import common
import pathlib
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="c69a06f3-3873-4d5d-8584-035e0921b4a8",
    platforms=["macos", "linux"],
    endpoint=[
        {
            "rule_id": "15019d7c-42e6-4cf7-88b0-0c3a6963e6f5",
            "rule_name": "Suspicious Recursive File Deletion via Built-In Utilities",
        }
    ],
    siem=[],
    techniques=["T1565", "T1485"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/xargs"
    masquerade2 = "/tmp/rm"
    # used only for linux at 2 places to enumerate xargs as parent process.
    working_dir = "/tmp/fake_folder/xargs"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
        common.copy_file(source, masquerade2)
        # As opposed to macos, where the masquerade is being projected as parent process,
        # in linux the working directory is being projected as parent process.
        # Hence, to simulate the parent process without many changes to execute logic
        # a fake folder structure is created for execution.
        # The execution working directory is changed to the fake folder, to simulate as xargs parent process in Linux.
        pathlib.Path(working_dir).mkdir(parents=True, exist_ok=True)
        os.chdir(working_dir)
    else:
        common.create_macos_masquerade(masquerade)
        common.create_macos_masquerade(masquerade2)

    # Execute command
    common.log("Launching fake builtin commands to recursively delete")
    command = f"{masquerade2} -rf arg1 arg2 arg3 arg4 arg5 arg6 arg7 arg8 arg9 arg10 /home/test"
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)
    if common.CURRENT_OS == "linux":
        common.remove_directory(working_dir)


if __name__ == "__main__":
    exit(main())
