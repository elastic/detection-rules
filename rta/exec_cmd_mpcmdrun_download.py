# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="219dee0a-48ad-4e17-ab59-783a619a7bd5",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'c6453e73-90eb-4fe7-a98c-cde7bbfc504a', 'rule_name': 'Remote File Download via MpCmdRun'}],
    techniques=['T1105'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    mpcmdrun = "C:\\Users\\Public\\MpCmdRun.exe"
    common.copy_file(EXE_FILE, mpcmdrun)

    # Execute command
    common.execute([mpcmdrun, "/c", "echo", "-DownloadFIle", "-Url", "-path"], timeout=10)
    common.remove_file(mpcmdrun)


if __name__ == "__main__":
    exit(main())
