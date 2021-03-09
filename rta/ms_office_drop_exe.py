# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Emulate MS Office Dropping an executable file to disk
# RTA: ms_office_drop_exe.py
# ATT&CK: T1064
# Description: MS Office writes executable file and it is run.

import os
import time

from . import common


@common.requires_os(common.WINDOWS)
def main():
    cmd_path = "c:\\windows\\system32\\cmd.exe"

    for office_app in ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]:
        common.log("Emulating office application %s" % office_app)
        office_path = os.path.abspath(office_app)
        common.copy_file(cmd_path, office_path)

        bad_path = os.path.abspath("bad-{}-{}.exe".format(hash(office_app), os.getpid()))
        common.execute([office_path, '/c', 'copy', cmd_path, bad_path])

        time.sleep(1)
        common.execute([bad_path, '/c', 'whoami'])

        # cleanup
        time.sleep(1)
        common.remove_files(office_app, bad_path)
        print("")


if __name__ == "__main__":
    exit(main())
