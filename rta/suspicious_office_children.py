# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Emulate Suspect MS Office Child Processes
# RTA: suspect_office_children.py
# signal.rule.name: Suspicious MS Office Child Process
# ATT&CK: T1064
# Description: Generates network traffic various children processes from emulated Office processes.

import os

from . import common
from . import RtaMetadata
from . import mshta_network


metadata = RtaMetadata(
    uuid="cd8e06c0-fc62-4932-8ef7-b767570e88eb",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "a624863f-a70d-417f-a7d2-7a404638d47f", "rule_name": "Suspicious MS Office Child Process"}],
    techniques=["T1566"],
)


@common.requires_os(metadata.platforms)
def main():
    mshta_path = os.path.abspath(mshta_network.__file__.replace(".pyc", ".py"))

    cmd_path = "c:\\windows\\system32\\cmd.exe"
    binaries = ["adobe.exe", "winword.exe", "outlook.exe", "excel.exe", "powerpnt.exe"]
    for binary in binaries:
        common.copy_file(cmd_path, binary)

    # Execute a handful of commands
    common.execute(["adobe.exe", "/c", "regsvr32.exe", "/s", "/?"], timeout=5, kill=True)
    common.execute(["winword.exe", "/c", "certutil.exe"], timeout=5, kill=True)
    common.execute(["outlook.exe", "/c", "powershell.exe", "-c", "whoami"], timeout=5, kill=True)
    common.execute(["excel.exe", "/c", "cscript.exe", "-x"], timeout=5, kill=True)
    # Test out ancestry for mshta
    common.execute(["powerpnt.exe", "/c", mshta_path])

    common.remove_files(*binaries)


if __name__ == "__main__":
    exit(main())
