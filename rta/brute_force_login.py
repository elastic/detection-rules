# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Brute Force Login Attempts
# RTA: brute_force_login.py
# ATT&CK: T1110
# Description: Simulates brute force or password spraying tactics.
#              Remote audit failures must be enabled to trigger: `auditpol /set /subcategory:"Logon" /failure:enable`

import random
import string
import sys
import time

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="35bb73a9-cafa-4b2c-81f0-a97e2afa5e1c",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {"rule_id": "e08ccd49-0380-4b2b-8d71-8000377d6e49", "rule_name": "Attempts to Brute Force an Okta User Account"}
    ],
    techniques=["T1110"],
)


@common.requires_os(metadata.platforms)
def main(username="rta-tester", remote_host=None):
    if not remote_host:
        common.log("A remote host is required to detonate this RTA", "!")
        return common.MISSING_REMOTE_HOST

    common.enable_logon_auditing(remote_host)

    common.log("Brute forcing login with invalid password against {}".format(remote_host))
    ps_command = """
    $PW = ConvertTo-SecureString "such-secure-passW0RD!" -AsPlainText -Force
    $CREDS = New-Object System.Management.Automation.PsCredential {username}, $PW
    Invoke-WmiMethod -ComputerName {host} -Class Win32_process -Name create -ArgumentList ipconfig -Credential $CREDS
    """
    command = [
        "powershell",
        "-c",
        ps_command.format(username=username, host=remote_host),
    ]

    # fail 4 times - the first 3 concurrently and wait for the final to complete
    for i in range(4):
        common.execute(command, wait=i == 3)

    time.sleep(1)

    common.log("Password spraying against {}".format(remote_host))

    # fail 5 times - the first 4 concurrently and wait for the final to complete
    for i in range(5):
        random_user = "".join(random.sample(string.ascii_letters, 10))
        command = [
            "powershell",
            "-c",
            ps_command.format(username=random_user, host=remote_host),
        ]
        common.execute(command, wait=i == 4)

    # allow time for audit event to process
    time.sleep(2)


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
