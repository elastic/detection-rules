# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="3c2c32fd-0856-4fc9-8a2d-81ed85e568b0",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '9b6813a1-daf1-457e-b0e6-0bb4e55b8a4c', 'rule_name': 'Persistence via WMI Event Subscription'}],
    techniques=['T1546', 'T1546.003'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    wmic = "C:\\Users\\Public\\wmic.exe"
    common.copy_file(EXE_FILE, wmic)

    common.execute([wmic, "/c", "echo", "create", "ActiveScriptEventConsumer"], timeout=5, kill=True)
    common.remove_files(wmic)


if __name__ == "__main__":
    exit(main())
