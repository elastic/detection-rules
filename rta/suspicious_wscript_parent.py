# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Suspicious WScript parent
# RTA: suspicious_wscript_parent.py
# ATT&CK: T1064, T1192, T1193
# Description: WScript run with suspicious parent processes

import os
import time

from . import common


@common.requires_os(common.WINDOWS)
def main():
    script_data = """
        WScript.CreateObject("wscript.shell")
    """
    script_path = ".\\hello.vbs"
    with open(script_path, 'w') as f:
        f.write(script_data)

    cmd_path = "c:\\windows\\system32\\cmd.exe"

    for application in ["outlook.exe", "explorer.exe", "chrome.exe", "firefox.exe"]:
        common.log("Emulating %s" % application)
        app_path = os.path.abspath(application)
        common.copy_file(cmd_path, app_path)

        common.execute([app_path, "/c", "wscript.exe", "script_path"], timeout=1, kill=True)

        common.log("Killing wscript window")
        common.execute('taskkill /IM wscript.exe')

        common.log('Cleanup %s' % app_path)
        common.remove_file(app_path)

    common.log("Sleep 5 to allow procecsses to finish")
    time.sleep(5)
    common.log('Cleanup %s' % script_path)
    common.remove_file(script_path)


if __name__ == "__main__":
    exit(main())
