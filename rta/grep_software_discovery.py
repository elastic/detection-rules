# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos", "linux"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Security Software Discovery via Grep",
            "rule_id": "870aecc0-cea4-4110-af3f-e02e9b373655",
        }
    ],
    "ENDPOINT": [
        {
            "rule_name": "Potential Security Software Discovery via Grep",
            "rule_id": "13eade2e-73dd-4fab-a511-88258635559d",
        }
    ],
}
TACTICS = ["TA0007"]
RTA_ID = "6ef908be-9ed3-413d-8d4d-94446107eecc"


@common.requires_os(PLATFORMS)
def main():

    masquerade = "/tmp/grep"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
    else:
        common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake grep commands to discover software")
    common.execute([masquerade, "testgreptestLittle Snitchtest"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
