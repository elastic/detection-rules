# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="8d6d519e-dca5-4fc0-acc3-e1b25209afc4",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '290aca65-e94d-403b-ba0f-62f320e63f51',
        'rule_name': 'UAC Bypass Attempt via Windows Directory Masquerading'
    }],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\proc.exe"
    common.copy_file(EXE_FILE, proc)

    common.execute([proc, "/c", "echo", "C:\\Windows \\system32\\a.exe"], timeout=5, kill=True)
    common.remove_files(proc)


if __name__ == "__main__":
    exit(main())
