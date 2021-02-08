# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

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


def schtasks(*args, **kwargs):
    return common.execute(['schtasks.exe'] + list(args), **kwargs)


@common.requires_os(common.WINDOWS)
def main():
    common.log("Scheduled Task Privilege Escalation")

    task_name = 'test-task-rta'
    file_path = os.path.abspath('task.log')
    command = "cmd.exe /c whoami.exe > " + file_path

    # Delete the task if it exists
    code, output = schtasks('/query', '/tn', task_name)
    if code == 0:
        schtasks('/delete', '/tn', task_name, '/f')

    code, output = schtasks('/create', '/tn', task_name, '/ru', 'system', '/tr', command, '/sc', 'onlogon')
    if code != 0:
        common.log("Error creating task", log_type="!")
        return

    # Run the task and grab the file
    code, output = schtasks('/run', '/tn', task_name)
    if code == 0:
        time.sleep(1)
        common.print_file(file_path)
        time.sleep(1)
        common.remove_file(file_path)

    schtasks('/delete', '/tn', task_name, '/f')


if __name__ == "__main__":
    main()
