# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="8c77b44c-fb6d-4082-b62d-147918c622d9",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Network Connection via Process with Unusual Arguments",
            "rule_id": "95601d8b-b969-4189-9744-090140ae29e6",
        },
    ],
    siem=[],
    techniques=["T1055", "T1036"],
)

EXE_FILE = common.get_path("bin", "regsvr32.exe")


@common.requires_os(metadata.platforms)
def main():

    common.log("Making connection using fake regsvr32.exe")
    common.execute([EXE_FILE], timeout=10, kill=True)


if __name__ == "__main__":
    exit(main())
