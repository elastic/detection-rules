# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Emulate Suspect MS Office Child Processes
# RTA: suspect_office_children.py
# signal.rule.name: Suspicious MS Office Child Process
# ATT&CK: T1064
# Description: Generates network traffic various children processes from emulated Office processes.

import os

from . import common
from . import mshta_network


@common.requires_os(common.WINDOWS)
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
