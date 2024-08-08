# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os

metadata = RtaMetadata(
    uuid="535959a4-5bad-44d8-9ebd-003d7ed0733c",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Egress Network Connection from RPM Package",
            "rule_id": "d20cd4ba-ff65-4e1c-8012-4241d449b16b"
        }
    ],
    techniques=["T1546", "T1543", "T1574", "T1195", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main():

    # Ensure the /var/tmp/ directory exists
    rpm_info_dir = "/var/tmp/"
    if not os.path.exists(rpm_info_dir):
        common.log(f"Creating directory {rpm_info_dir}")
        os.makedirs(rpm_info_dir)

    # Path for the fake RPM package executable
    masquerade = os.path.join(rpm_info_dir, "rpm-tmp.rta")
    source = common.get_path("bin", "netcon_exec_chain.elf")

    common.log("Creating a fake RPM package..")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(['chmod', '+x', masquerade])

    # Execute the fake RPM package
    common.log("Executing the fake RPM package..")
    commands = [
        masquerade,
        'exec',
        '-c',
        'exec /var/tmp/rpm-tmp.rta netcon -h 8.8.8.8 -p 53'
    ]
    common.execute([*commands], timeout=5, kill=True, shell=True)

    # Cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
