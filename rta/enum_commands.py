# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Common Enumeration Commands
# RTA: enum_commands.py
# ATT&CK: T1007, T1016, T1018, T1035, T1049, T1057, T1063, T1069, T1077, T1082, T1087, T1124, T1135
# Description: Executes a list of administration tools commonly used by attackers for enumeration.

import argparse
import random

from . import common


@common.requires_os(common.WINDOWS)
def main(args=None):
    slow_commands = [
        "gpresult.exe /z",
        "systeminfo.exe"
    ]

    commands = [
        "ipconfig /all",
        "net localgroup administrators",
        "net user",
        "net user administrator",
        "net user /domain"
        "tasklist",
        "net view",
        "net view /domain",
        "net view \\\\%s" % common.get_ip(),
        "netstat -nao",
        "whoami",
        "hostname",
        "net start",
        "tasklist /svc",
        "net time \\\\%s" % common.get_ip(),
        "net use",
        "net view",
        "net start",
        "net accounts",
        "net localgroup",
        "net group",
        "net group \"Domain Admins\" /domain",
        "net share",
        "net config workstation",
    ]

    commands.extend(slow_commands)

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--sample', dest="sample", default=len(commands), type=int,
                        help="Number of commands to run, choosen at random from the list of enumeration commands")
    args = parser.parse_args(args)
    sample = min(len(commands), args.sample)

    if sample < len(commands):
        random.shuffle(commands)

    common.log("Running {} out of {} enumeration commands\n".format(sample, len(commands)))
    for command in commands[0:sample]:

        common.log("About to call {}".format(command))
        if command in slow_commands:
            common.execute(command, kill=True, timeout=15)
            common.log("[output surpressed]", log_type='-')
        else:
            common.execute(command)


if __name__ == "__main__":
    exit(main())
