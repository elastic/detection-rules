# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="717c2fa4-7b5f-4034-a765-0a15aaf514f1",
    platforms=["windows"],
    endpoint=[{
        'rule_id': 'e2554e2b-7333-4379-88af-67e5bfac677a',
        'rule_name': 'Suspicious Execution via Compiled HTML File'
    }],
    siem=[],
    techniques=['T1566', 'T1566.001', 'T1218', 'T1218.001'],
)


@common.requires_os(metadata.platforms)
def main():
    hh = "C:\\Windows\\hh.exe"

    common.execute([hh, "C:\\Users\\RTA\\Downloads\\a"], timeout=2, kill=True)
    common.remove_files(hh)


if __name__ == "__main__":
    exit(main())
