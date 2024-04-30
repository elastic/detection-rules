# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ad0986cb-b5ef-41ad-9b40-8d708dc28844",
    platforms=["windows"],
    endpoint=[
        {
        'rule_id': 'a5416b1f-fc3f-4162-936d-34086689c3b0',
        'rule_name': 'DLL Execution via Visual Studio Live Share'
        }
    ],
    siem=[],
    techniques=['T1218'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    vslsagent = "C:\\Users\\Public\\vsls-agent.exe"
    common.copy_file(EXE_FILE, vslsagent)

    common.execute([vslsagent, "/c", "echo", "--agentExtensionPath"], timeout=5, kill=True)
    common.remove_files(vslsagent)


if __name__ == "__main__":
    exit(main())
