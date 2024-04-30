# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="be6619a2-324a-443b-9f23-2dc84733c847",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Suspicious Microsoft IIS Worker Descendant",
            "rule_id": "89c9c5a0-a136-41e9-8cc8-f21ef5ad894b"
        }
    ],
    siem=[
        {
            "rule_id": "f81ee52c-297e-46d9-9205-07e66931df26",
            "rule_name": "Microsoft Exchange Worker Spawning Suspicious Processes"
        },
        {
            "rule_name": "Web Shell Detection: Script Process Child of Common Web Processes",
            "rule_id": "2917d495-59bd-4250-b395-c29409b76086"
        }],
    techniques=['T1190', 'T1059', 'T1059.001', 'T1059.003', 'T1505', 'T1505.003'],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    w3wp = "C:\\Users\\Public\\w3wp.exe"
    common.copy_file(EXE_FILE, w3wp)

    common.execute([w3wp, "/c", "echo", "MSExchange1AppPool", "; cmd.exe"], timeout=10, kill=True)
    common.remove_file(w3wp)


if __name__ == "__main__":
    exit(main())
