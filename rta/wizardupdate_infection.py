# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1048ff54-4ac4-441f-839d-e4d06a0cb211",
    platforms=["macos"],
    endpoint=[
        {"rule_id": "eb78fa0f-5e8a-4c15-a099-e904c4a226e6", "rule_name": "Potential WizardUpdate Malware Infection"}
    ],
    siem=[],
    techniques=[""],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/curl"
    common.create_macos_masquerade(masquerade)

    # Execute commands
    common.log("Launching fake curl commands to mimic WizardUpdate infection")
    common.execute([masquerade, "test_intermediate_agent_testmachine_idtest"], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
