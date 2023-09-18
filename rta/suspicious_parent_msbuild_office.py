# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b279f4c3-2269-4557-b267-68dc2f88019b",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'c5dc3223-13a2-44a2-946c-e9dc0aa0449c',
        'rule_name': 'Microsoft Build Engine Started by an Office Application'
    }],
    techniques=['T1127', 'T1127.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    excel = "C:\\Users\\Public\\excel.exe"
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    common.copy_file(EXE_FILE, excel)
    common.copy_file(EXE_FILE, msbuild)

    # Execute command
    common.execute([excel, "/c", msbuild], timeout=2, kill=True)
    common.remove_files(excel, msbuild)


if __name__ == "__main__":
    exit(main())
