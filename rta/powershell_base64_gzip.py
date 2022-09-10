# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PowerShell with base64/gzip
# RTA: powershell_base64_gzip.py
# ATT&CK: T1140
# Description: Calls PowerShell with command-line that contains base64/gzip

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="38defc7e-7234-45a2-83ef-e845d0eba3f2",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            "rule_id": "81fe9dc6-a2d7-4192-a2d8-eed98afc766a",
            "rule_name": "PowerShell Suspicious Payload Encoded and Compressed",
        }
    ],
    techniques=["T1140", "T1027", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("PowerShell with base64/gzip")

    command = "powershell.exe -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String(aaa)"  # noqa: E501
    common.execute(command)


if __name__ == "__main__":
    exit(main())
