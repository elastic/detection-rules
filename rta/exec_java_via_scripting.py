# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="a3b26c9e-6910-43f7-93b2-84cc777e54f4",
    platforms=["windows"],
    endpoint=[
        {
            'rule_id': '15b1d979-5be0-4e7f-9202-0c4cfd76b146',
            'rule_name': 'Suspicious Java Execution via a Windows Script'
        },
        {'rule_id': '16c84e67-e5e7-44ff-aefa-4d771bcafc0c', 'rule_name': 'Execution from Unusual Directory'},
        {'rule_id': '35dedf0c-8db6-4d70-b2dc-a133b808211f', 'rule_name': 'Binary Masquerading via Untrusted Path'},
        {'rule_id': '23e29d07-7584-465e-8a6d-912d9ea254a6', 'rule_name': 'Suspicious Image Load via Windows Scripts'}
    ],
    siem=[],
    techniques=['T1059', 'T1059.005', 'T1059.007'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(common.WINDOWS)
def main():
    path = "C:\\Program Files\\Java\\jrertaendgametest\\bin\\"
    argpath = "C:\\\"Program Files\"\\Java\\jrertaendgametest\\bin\\Javafake.exe"
    cscript = "C:\\Users\\Public\\cscript.exe"
    executable = path + "Javafake.exe"

    if not Path(path).is_dir():
        Path(path).mkdir(parents=True)
    else:
        pass
    common.copy_file(EXE_FILE, cscript)
    common.copy_file(EXE_FILE, executable)

    # Execute command
    common.execute([cscript, "/c", argpath, ("iwr google.com -UseBasicParsing -UserAgent "
                    "'C:\\Users\\Public\\' -SessionVariable '-jar'")], timeout=10)
    common.remove_files(cscript, executable)


if __name__ == "__main__":
    exit(main())
