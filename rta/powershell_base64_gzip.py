# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PowerShell with base64/gzip
# RTA: powershell_base64_gzip.py
# ATT&CK: T1140
# Description: Calls PowerShell with command-line that contains base64/gzip

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("PowerShell with base64/gzip")

    command = 'powershell.exe -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String(aaa)'  # noqa: E501
    common.execute(command)


if __name__ == "__main__":
    exit(main())
