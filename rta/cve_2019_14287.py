# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="df91f5f2-a0a0-47e8-848b-d01526a43d60",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential Sudo Privilege Escalation via CVE-2019-14287",
            "rule_id": "b382c343-892d-46e1-8fad-22576a086598",
        },
    ],
    siem=[
        {
            "rule_name": "Potential Sudo Privilege Escalation via CVE-2019-14287",
            "rule_id": "8af5b42f-8d74-48c8-a8d0-6d14b4197288",
        },
    ],
    techniques=["T1068"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/sudo"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake sudo command to simulate CVE-2019-14287")
    common.execute([masquerade, "-u#-1"], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
