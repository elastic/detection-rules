# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c2786f8d-d565-494d-84e2-5dcb2da711c4",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "SolarMarker Backdoor Registry Modification", "rule_id": "f7e6d239-9af5-42e3-8d23-91e7188a5cb0"}
    ],
    siem=[],
    techniques=["T1112", "T1546"],
)


@common.requires_os(metadata.platforms)
def main():
    reg = "C:\\Windows\\System32\\reg.exe"

    payloadcontent = (
        "Just some Powershell random words to make it to the 200 characters, remember to drink water and"
        "take a walk twice a day, check if your dog has enought food and water too, ah, and go to the"
        "gym, you can do it!!!!"
    )
    regpath = "HKEY_CURRENT_USER\\Software\\Classes\\simul8\\shell\\open"

    # Execute command
    common.log("Creating reg key using fake msiexec")
    common.execute(
        [
            reg,
            "add",
            regpath,
            "/v",
            "command",
            "/t",
            "REG_SZ",
            "/d",
            payloadcontent,
            "/f",
        ],
        timeout=5,
        kill=True,
    )

    common.execute([reg, "delete", regpath, "/f"], timeout=5, kill=True)


if __name__ == "__main__":
    exit(main())
