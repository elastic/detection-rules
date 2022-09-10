# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1bb39cea-8bf2-4b1f-a70e-69f6074a1fb4",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {"rule_name": "Unusual Network Connection via RunDLL32", "rule_id": "2e708541-c6e8-4ded-923f-78a6c160987e"},
    ],
    siem=[],
    techniques=["T1055", "T1218", "T1036"],
)

EXE_FILE = common.get_path("bin", "regsvr32.exe")


@common.requires_os(metadata.platforms)
def main():
    binary = "rundll32.exe"
    common.copy_file(EXE_FILE, binary)

    common.log("Making connection using fake rundll32.exe")
    common.execute([binary])
    common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
