# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="07eaba7d-c0ff-4480-87cf-5ad39805dc92",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '201200f1-a99b-43fb-88ed-f65a45c4972c', 'rule_name': 'Suspicious .NET Code Compilation'}],
    techniques=['T1027', 'T1027.004'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    wscript = "C:\\Users\\Public\\wscript.exe"
    csc = "C:\\Users\\Public\\csc.exe"
    common.copy_file(EXE_FILE, wscript)
    common.copy_file(EXE_FILE, csc)

    # Execute command
    common.execute([wscript, "/c", csc], timeout=2, kill=True)
    common.remove_files(wscript, csc)


if __name__ == "__main__":
    exit(main())
