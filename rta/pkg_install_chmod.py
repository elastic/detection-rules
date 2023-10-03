# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="caa6feb7-cc17-425f-996f-b1b69efa93e2",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "File Made Executable via Pkg Install Script", "rule_id": "75f5d51a-218f-4d5b-80e5-eb74e498fde4"},
        {
            "rule_name": "File Made Executable by Suspicious Parent Process",
            "rule_id": "42ab2c0f-b10d-467d-8c6d-def890cf3f68",
        },
        {
            "rule_name": "Suspicious File Create via Pkg Install Script",
            "rule_id": "f06d9987-33f8-44b7-b815-c1f66fb39d25",
        },
    ],
    siem=[],
    techniques=["T1222", "T1222.002", "T1564", "T1546", "T1546.016"],
)


@common.requires_os(*metadata.platforms)
def main():

    dest_file = "/tmp/test.py"
    source_file = "/tmp/test.txt"
    masquerade = "/Users/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    command = f"chmod +x {source_file}"
    common.log("Launching fake bash commands to execute chmod on file via pkg install")
    with common.temporary_file("testing", source_file):
        common.execute(
            [
                masquerade,
                "childprocess",
                command,
                "childprocess",
                f"cp {source_file} {dest_file}",
                "childprocess",
                "/tmp/PKInstallSandbox.*/Scripts/*/postinstall",
            ],
            timeout=10,
            kill=True,
        )

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(dest_file)


if __name__ == "__main__":
    exit(main())
