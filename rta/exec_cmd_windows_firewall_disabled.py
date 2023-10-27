# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1286c142-8acc-4b58-a7c1-572870c81bc1",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'f63c8e3c-d396-404f-b2ea-0379d3942d73', 'rule_name': 'Windows Firewall Disabled via PowerShell'}],
    techniques=['T1562', 'T1562.004'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "echo", "Set-NetFirewallProfile", "-Enabled", "False", "-All"], timeout=2)


if __name__ == "__main__":
    exit(main())
