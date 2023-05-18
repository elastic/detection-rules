# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="dc1baf0d-8048-481a-b142-73313181fe31",
    platforms=["linux"],
    endpoint=[
        {"rule_name": "Privilege Escalation via PKEXEC Exploitation", "rule_id": "30c89cc9-d93c-4134-a976-58f8413f2f32"}
    ],
    siem=[],
    techniques=["T1574", "T1068"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Executing command to simulate privilege escalation via PKEXEC exploitation")
    # The exploit reproduction is available for commercial usage via MIT License
    # https://github.com/berdav/CVE-2021-4034/blob/main/LICENSE
    # The RTA script has complied binary in the /bin folder. Refer src folder for the origin code.

    exploit_path = common.get_path("bin", "pkexec_cve20214034", "cve-2021-4034")
    common.execute(exploit_path)


if __name__ == "__main__":
    exit(main())
