# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PsExec Lateral Movement
# RTA: lateral_command_psexec.py
# ATT&CK: T1035, T1077
# Description: Runs PSExec to move laterally

import sys

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_id": "55d551c6-333b-4665-ab7e-5d14a59715ce",
            "rule_name": "PsExec Network Connection",
        }
    ],
    "ENDPOINT": [],
}
TACTICS = ["TA0008", "TA0002"]
RTA_ID = "90cf6001-11a7-410b-b259-cf20a029b929"


@common.requires_os(PLATFORMS)
@common.dependencies(common.PS_EXEC)
def main(remote_host=None):
    remote_host = remote_host or common.get_ip()
    common.log("Performing PsExec to %s" % remote_host)
    common.execute([common.PS_EXEC, "\\\\%s" % remote_host, "-accepteula", "ipconfig"])


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
