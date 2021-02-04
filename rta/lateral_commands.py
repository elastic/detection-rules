# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Lateral Movement Commands
# RTA: lateral_commands.py
# signal.rule.name: Local Service Commands
# signal.rule.name: Local Scheduled Task Commands
# signal.rule.name: Whoami Process Activity
# ATT&CK: T1021, T1047, T1077, T1124, T1126
# Description: Runs various Windows commands typically used by attackers to move laterally from the local machine.

import os
import re
import sys

from . import common

MY_APP = common.get_path("bin", "myapp.exe")


@common.requires_os(common.WINDOWS)
@common.dependencies(MY_APP)
def main(remote_host=None):
    remote_host = remote_host or common.get_ip()
    common.log("Attempting to laterally move to %s" % remote_host)

    remote_host = common.get_ipv4_address(remote_host)
    common.log("Using ip address %s" % remote_host)

    # Put the hostname in quotes for WMIC, but leave it as is
    if not re.match(common.IP_REGEX, remote_host):
        wmi_node = '"{}"'.format(remote_host)
    else:
        wmi_node = remote_host

    commands = [
        "sc.exe \\\\{host} create test_service binPath= %s" % MY_APP,
        "sc.exe \\\\{host} config test_service binPath= c:\\windows\\system32\\ipconfig.exe",
        "sc.exe \\\\{host} failure test_service command= c:\\windows\\system32\\net.exe",
        "sc.exe \\\\{host} start test_service",
        "sc.exe \\\\{host} delete test_service",
        "wmic.exe /node:{wmi_node} process call create ipconfig.exe",
        "wmic.exe /node:{wmi_node} path WIN32_USERACCOUNT where(name='vagrant') set passwordexpires='false'",
        "net.exe time \\\\{host}",
        "net.exe use \\\\{host}\\admin$",
        "net.exe use \\\\{host}\\admin$ /delete",
        "net.exe use \\\\{host}\\c$",
        "net.exe use \\\\{host}\\c$ /delete",
    ]

    for command in commands:
        common.execute(command.format(host=remote_host, wmi_node=wmi_node))

    _, whoami = common.execute(["whoami"])
    _, hostname = common.execute(["hostname"])

    domain, user = whoami.lower().split("\\")
    hostname = hostname.lower()
    schtasks_host = remote_host

    # Check if the account is local or a domain
    if domain in (hostname, "NT AUTHORITY"):
        common.log("Need password for remote scheduled task in workgroup. Performing instead on %s." % common.get_ip())
        schtasks_host = common.get_ip()

    task_name = "test_task-%d" % os.getpid()
    schtask_commands = [
        r"schtasks /s {host} /delete /tn {name} /f",
        r"schtasks /s {host} /create /SC MONTHLY /MO first /D SUN /tn {name} /tr c:\windows\system32\ipconfig.exe /f",

        r"schtasks /s {host} /run /tn {name}",
        r"schtasks /s {host} /delete /tn {name} /f",

    ]

    for command in schtask_commands:
        command = command.format(host=schtasks_host, name=task_name)
        common.execute(command)

    # Remote powershell
    common.execute(["C:\\Windows\\system32\\wsmprovhost.exe", "-Embedding"], timeout=5, kill=True)


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
