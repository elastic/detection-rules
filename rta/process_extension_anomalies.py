# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Executable with Unusual Extensions
# RTA: process_extension_anomalies.py
# ATT&CK: T1036
# Description: Creates processes with anomalous extensions

from . import common

MY_APP = common.get_path("bin", "myapp.exe")


@common.requires_os(common.WINDOWS)
@common.dependencies(MY_APP)
def main():
    anomalies = [
        "bad.pif",
        "evil.cmd",
        "evil.gif",
        "bad.pdf",
        "suspicious.bat",
        "hiding.vbs",
        "evil.xlsx"
    ]

    for path in anomalies:
        common.log("Masquerading python as %s" % path)
        common.copy_file(MY_APP, path)
        common.execute([path])
        common.remove_file(path)


if __name__ == "__main__":
    exit(main())
