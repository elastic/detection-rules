# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Windows Core Process Masquerade
# RTA: process_name_masquerade.py
# ATT&CK: T1036
# Description: Creates several processes which mimic core Windows process names but that are not those executables.

import os

from . import common

MY_APP = common.get_path("bin", "myapp.exe")


@common.requires_os(common.WINDOWS)
@common.dependencies(MY_APP)
def main():
    masquerades = [
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "explorer.exe",
    ]

    for name in masquerades:
        path = os.path.abspath(name)
        common.copy_file(MY_APP, path)
        common.execute(path, timeout=3, kill=True)
        common.remove_file(path)


if __name__ == "__main__":
    exit(main())
