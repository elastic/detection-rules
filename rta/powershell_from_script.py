# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PowerShell Launched from Script
# RTA: powershell_from_script.py
# signal.rule.name: Windows Script Executing PowerShell
# ATT&CK: T1064, T1192, T1193
# Description: Creates a javascript file that will launch powershell.

import os
import time

from . import common


@common.requires_os(common.WINDOWS)
def main():
    # Write script
    script_file = os.path.abspath("launchpowershell.vbs")
    script = """Set objShell = CreateObject("Wscript.shell")
    objShell.run("powershell echo 'Doing evil things...'; sleep 3")
    """
    with open(script_file, 'w') as f:
        f.write(script)

    # Execute script
    for proc in ["wscript", "cscript"]:
        common.execute([proc, script_file])
        time.sleep(3)

    # Clean up
    common.remove_file(script_file)

    return common.SUCCESS


if __name__ == "__main__":
    exit(main())
