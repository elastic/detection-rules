# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7253d78c-8a68-4073-b20a-fbab9d4daf23",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '1d276579-3380-4095-ad38-e596a01bc64f',
        'rule_name': 'Remote File Download via Script Interpreter'
    }],
    techniques=['T1105'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    wscript = "C:\\Users\\Public\\wscript.exe"
    fake_exe = "C:\\Users\\Public\\a.exe"
    common.copy_file(EXE_FILE, wscript)

    # Execute command
    common.execute([wscript, "/c", f"Test-NetConnection -ComputerName google.com -Port 443 | Out-File {fake_exe}"],
                   timeout=10)
    common.remove_files(fake_exe, wscript)


if __name__ == "__main__":
    exit(main())
