# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: WMI Incoming Lateral Movement
# RTA: wmi_incoming_logon.py
# ATT&CK: T1047
# Description: Uses PS WMI to trigger 2 logon events via wmi and 1 control logon, which should result in 2 alerts total

import sys

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="3adf005f-94b8-4b34-8994-d5a3dc6666c2",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "f3475224-b179-4f78-8877-c2bd64c26b88", "rule_name": "WMI Incoming Lateral Movement"}],
    techniques=["T1047"],
)


@common.requires_os(metadata.platforms)
def main(remote_host=None):
    if not remote_host:
        common.log("A remote host is required to detonate this RTA", "!")
        return common.MISSING_REMOTE_HOST

    common.enable_logon_auditing(remote_host)

    common.log("Attempting to trigger a remote logon on {}".format(remote_host))

    commands = [
        "Invoke-WmiMethod -ComputerName {} -Class Win32_process -Name create -ArgumentList {}".format(remote_host, c)
        for c in ("ipconfig", "netstat")
    ]

    # trigger twice
    for command in commands:
        common.execute(["powershell", "-c", command])

    # this should not trigger an alert
    common.execute(["net.exe", "time", "\\\\{}".format(remote_host)])


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
