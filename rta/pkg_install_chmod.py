
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
        {"rule_name": "File Made Executable by Suspicious Parent Process", "rule_id": "42ab2c0f-b10d-467d-8c6d-def890cf3f68"},
    ],
    siem=[],
    techniques=["T1222", "T1222.002"],
)


@common.requires_os(metadata.platforms)
def main():


    masquerade = "/Users/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    command = "chmod +x /tmp/test.txt"
    common.log("Launching fake bash commands to execute chmod on file via pkg install")
    with common.temporary_file("testing", "/tmp/test.txt"):
        common.execute([masquerade, "childprocess", command, "/tmp/PKInstallSandbox.*/Scripts/*/postinstall"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())