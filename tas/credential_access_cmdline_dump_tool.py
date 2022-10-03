# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e4d9d172-8078-4aa0-a7bc-154848efb965",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '00140285-b827-4aee-aa09-8113f58a08f3', 'rule_name': 'Potential Credential Access via Windows Utilities'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    processdump = "C:\\Users\\Public\\processdump.exe"
    common.copy_file(EXE_FILE, processdump)

    # Execute command
    common.execute([processdump], timeout=1, kill=True)
    common.remove_file(processdump)


if __name__ == "__main__":
    exit(main())
