# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a37316f1-2828-45d2-85ea-1783bb9b9982",
    platforms=["windows"],
    endpoint=[{
        'rule_id': 'ed77616c-8f97-472b-bb15-532af004e82a',
        'rule_name': 'Suspicious DLLRegisterServer Execution via MSIEXEC'
    }],
    siem=[],
    techniques=['T1218', 'T1218.007'],
)


@common.requires_os(*metadata.platforms)
def main():
    msiexec = "C:\\Windows\\System32\\msiexec.exe"

    common.execute([msiexec, "/z"], timeout=5, kill=True)
    common.remove_files(msiexec)


if __name__ == "__main__":
    exit(main())
