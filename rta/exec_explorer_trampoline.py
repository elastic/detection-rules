# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="5e911636-6f68-40d3-b1ef-7a951a397cc9",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Execution of Commonly Abused Utilities via Explorer Trampoline",
            "rule_id": "5e8498bb-8cc0-412f-9017-793d94ab76a5",
        }
    ],
    siem=[],
    techniques=["T1218", "T1566", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    explorer = "C:\\Users\\Public\\explorer.exe"
    common.copy_file(EXE_FILE, explorer)

    common.execute(
        [
            explorer,
            "-c",
            "echo",
            "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}",
            ";mshta",
        ],
        timeout=10,
    )
    common.remove_files(explorer)


if __name__ == "__main__":
    exit(main())
