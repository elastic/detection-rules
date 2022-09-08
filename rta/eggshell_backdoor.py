# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="be090f8e-dc7b-41eb-9c7e-74a0aed0dad1",
    platforms=["macos", "linux"],
    endpoint=[{"rule_name": "EggShell Backdoor Execution", "rule_id": "feed7842-34a6-4764-b858-6e5ac01a5ab7"}],
    siem=[{"rule_name": "EggShell Backdoor Execution", "rule_id": "41824afb-d68c-4d0e-bfee-474dac1fa56e"}],
    techniques=["T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/eggshell"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
    else:
        common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake commands for EggShell backdoor behavior")
    common.execute([masquerade, "eyJkZWJ1ZyI6test"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
