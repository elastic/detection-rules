# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Scheduled Task Privilege Escalation
# RTA: schtask_escalation.py
# signal.rule.name: Local Scheduled Task Commands
# signal.rule.name: Whoami Process Activity
# signal.rule.name: Svchost spawning Cmd
# signal.rule.name: Net command via SYSTEM account
# ATT&CK: T1053

import os
import time

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1a61241e-5b1b-44ec-8c9f-3ae4652550be",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {"rule_id": "afcce5ad-65de-4ed2-8516-5e093d3ac99a", "rule_name": "Local Scheduled Task Creation"},
        {"rule_id": "ef862985-3f13-4262-a686-5f357bbb9bc2", "rule_name": "Whoami Process Activity"},
        {"rule_id": "fd7a6052-58fa-4397-93c3-4795249ccfa2", "rule_name": "Svchost spawning Cmd"},
    ],
    techniques=["T1033", "T1053", "T1059"],
)


def schtasks(*args, **kwargs):
    return common.execute(["schtasks.exe"] + list(args), **kwargs)


@common.requires_os(metadata.platforms)
def main():
    common.log("Scheduled Task Privilege Escalation")

    task_name = "test-task-rta"
    file_path = os.path.abspath("task.log")
    command = "cmd.exe /c whoami.exe > " + file_path

    # Delete the task if it exists
    code, output = schtasks("/query", "/tn", task_name)
    if code == 0:
        schtasks("/delete", "/tn", task_name, "/f")

    code, output = schtasks("/create", "/tn", task_name, "/ru", "system", "/tr", command, "/sc", "onlogon")
    if code != 0:
        common.log("Error creating task", log_type="!")
        return

    # Run the task and grab the file
    code, output = schtasks("/run", "/tn", task_name)
    if code == 0:
        time.sleep(1)
        common.print_file(file_path)
        time.sleep(1)
        common.remove_file(file_path)

    schtasks("/delete", "/tn", task_name, "/f")


if __name__ == "__main__":
    main()
