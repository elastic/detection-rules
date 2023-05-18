# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6e84852e-b8a2-4158-971e-c5148d969d2a",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '5bc7a8f8-4de8-4af4-bea4-cba538e54a5c', 'rule_name': 'Suspicious Execution via DotNet Remoting'}],
    techniques=['T1218'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    addinproc = "C:\\Users\\Public\\AddInProcess.exe"
    common.copy_file(EXE_FILE, addinproc)

    # Execute command
    common.execute([addinproc, "/guid:32a91b0f-30cd-4c75-be79-ccbd6345de99", "/pid:123"], timeout=10)
    common.remove_file(addinproc)


if __name__ == "__main__":
    exit(main())
