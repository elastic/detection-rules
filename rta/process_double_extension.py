# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Double Process Extension
# RTA: process_double_extension.py
# ATT&CK: T1036
# Description: Create and run a process with a double extension.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="27694576-0454-40b3-9823-e29719c53750",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            "rule_id": "8b2b3a62-a598-4293-bc14-3d5fa22bb98f",
            "rule_name": "Executable File Creation with Multiple Extensions",
        }
    ],
    techniques=["T1204", "T1036"],
)


MY_APP = common.get_path("bin", "myapp_x64.exe")


@common.requires_os(metadata.platforms)
@common.dependencies(MY_APP)
def main():
    anomalies = ["test.txt.exe"]

    for path in anomalies:
        common.log("Masquerading process as %s" % path)
        common.copy_file(MY_APP, path)
        common.execute([path])
        common.remove_file(path)


if __name__ == "__main__":
    exit(main())
