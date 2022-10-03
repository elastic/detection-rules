# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d5569926-7323-4fc7-a3cc-74d7c416bc36",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'f675872f-6d85-40a3-b502-c0d2ef101e92', 'rule_name': 'Delete Volume USN Journal with Fsutil'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    fsutil = "C:\\Users\\Public\\fsutil.exe"
    common.copy_file(EXE_FILE, fsutil)

    # Execute command
    common.execute([fsutil, "/c", "echo", "usn", "deletejournal"], timeout=10)
    common.remove_file(fsutil)


if __name__ == "__main__":
    exit(main())
