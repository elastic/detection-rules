# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="bc4c85e7-c2c6-497c-a52e-7c8896a79ab2",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'c3b915e0-22f3-4bf7-991d-b643513c722f', 'rule_name': 'Persistence via BITS Job Notify Cmdline'}],
    techniques=['T1197'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    svchost = "C:\\Users\\Public\\svchost.exe"
    child = "C:\\Users\\Public\\child.exe"
    common.copy_file(EXE_FILE, child)
    common.copy_file(EXE_FILE, svchost)

    common.execute([svchost, "echo", "BITS", ";", child], timeout=5, kill=True)
    common.remove_files(child, svchost)


if __name__ == "__main__":
    exit(main())
