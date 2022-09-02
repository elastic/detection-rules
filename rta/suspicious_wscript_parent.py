# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious WScript parent
# RTA: suspicious_wscript_parent.py
# signal.rule.name: Suspicious MS Outlook Child Process
# ATT&CK: T1064, T1192, T1193
# Description: WScript run with suspicious parent processes

import os
import time

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a3cdd478-b817-4513-bb3d-897a5f92c836",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {"rule_id": "32f4675e-6c49-4ace-80f9-97c9259dca2e", "rule_name": "Suspicious MS Outlook Child Process"},
        {"rule_id": "a624863f-a70d-417f-a7d2-7a404638d47f", "rule_name": "Suspicious MS Office Child Process"},
    ],
    techniques=["T1566"],
)


@common.requires_os(metadata.platforms)
def main():
    script_data = """
        WScript.CreateObject("wscript.shell")
    """
    script_path = ".\\hello.vbs"
    with open(script_path, "w") as f:
        f.write(script_data)

    cmd_path = "c:\\windows\\system32\\cmd.exe"

    for application in ["outlook.exe", "explorer.exe", "chrome.exe", "firefox.exe"]:
        common.log("Emulating %s" % application)
        app_path = os.path.abspath(application)
        common.copy_file(cmd_path, app_path)

        common.execute([app_path, "/c", "wscript.exe", "script_path"], timeout=1, kill=True)

        common.log("Killing wscript window")
        common.execute("taskkill /IM wscript.exe")

        common.log("Cleanup %s" % app_path)
        common.remove_file(app_path)

    common.log("Sleep 5 to allow procecsses to finish")
    time.sleep(5)
    common.log("Cleanup %s" % script_path)
    common.remove_file(script_path)


if __name__ == "__main__":
    exit(main())
