# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d1d1978f-4aa3-4f06-868b-d64ddf24fe6c",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '55d551c6-333b-4665-ab7e-5d14a59715ce', 'rule_name': 'PsExec Network Connection'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    psexec = "C:\\Users\\Public\\psexec.exe"
    common.copy_file(EXE_FILE, psexec)

    # Execute command
    common.execute([psexec, "/c", "echo", "-accepteula"], timeout=10)
    common.execute([psexec, "/c", f"iwr google.com -UseBasicParsing"], timeout=10)


if __name__ == "__main__":
    exit(main())
