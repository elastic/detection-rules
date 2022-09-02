# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="37b8d4d9-5acc-40c0-bc78-aba24a2c3f80",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "UAC Bypass via DiskCleanup Scheduled Task Hijack",
            "rule_id": "d487049e-381d-44ad-9ec9-d23e88dbf573",
        }
    ],
    siem=[],
    techniques=["T1548"],
)


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.execute([powershell, "/autoclean", "/d"], timeout=2, kill=True)


if __name__ == "__main__":
    exit(main())
