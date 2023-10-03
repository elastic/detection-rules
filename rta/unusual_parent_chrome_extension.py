# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9e31b8ae-c0a6-46c9-9634-d1aebceea541",
    platforms=["windows"],
    endpoint=[{
        'rule_id': 'd7fda3d7-fe77-49c2-8b50-d28a6da206c4',
        'rule_name': 'Chromium Extension Loaded from Unusual Parent'
    }],
    siem=[],
    techniques=['T1176'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\proc.exe"
    childproc = "C:\\Users\\Public\\childproc.exe"
    common.copy_file(EXE_FILE, proc)
    common.copy_file(EXE_FILE, childproc)

    common.execute([proc, "/c", "echo", f"--load-extension; & {childproc}"], timeout=5, kill=True)
    common.remove_files(childproc, proc)


if __name__ == "__main__":
    exit(main())
