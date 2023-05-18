# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ca0cc06d-6a8f-4d9b-a9c2-9315c62f924a",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Suspicious Execution via Windows Management Instrumentation",
            "rule_id": "7e554c18-6435-41ce-b57b-d0ac3b73817f",
        },
        {"rule_name": "Microsoft Office File Execution via WMI", "rule_id": "792411bd-59ef-4ac0-89be-786d52d1a5c8"},
    ],
    siem=[],
    techniques=["T1047", "T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    server, ip, port = common.serve_web()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    winword = "C:\\Users\\Public\\winword.exe"
    wmiprvse = "C:\\Users\\Public\\wmiprvse.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, winword)
    common.copy_file(EXE_FILE, wmiprvse)
    common.copy_file(EXE_FILE, dropped)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    common.execute([winword, "/c", cmd], timeout=10)
    common.execute([wmiprvse, "/c", dropped], timeout=10, kill=True)
    common.remove_file(winword)
    common.remove_file(dropped)


if __name__ == "__main__":
    exit(main())
