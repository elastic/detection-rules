# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="81adc847-2965-4a4b-8d3c-91e541c85ab4",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '9ccf3ce0-0057-440a-91f5-870c6ad39093',
        'rule_name': 'Command Shell Activity Started via RunDLL32'
    }],
    techniques=['T1059', 'T1059.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    common.copy_file(EXE_FILE, rundll32)

    # Execute command
    common.execute([rundll32, "/c", cmd], timeout=2, kill=True)
    common.remove_file(rundll32)


if __name__ == "__main__":
    exit(main())
