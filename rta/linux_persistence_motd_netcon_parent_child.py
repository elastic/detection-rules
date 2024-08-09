# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="a67ba2b1-cace-4cb9-9b7e-12c9ffe136cb",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Egress Network Connection by MOTD Child",
            "rule_id": "da02d81a-d432-4cfe-8aa4-fc1a31c29c98"
        }
    ],
    techniques=["T1037", "T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main():

    # Path for the fake motd executable
    masquerade = "/etc/update-motd.d/rta"
    source = common.get_path("bin", "netcon_exec_chain.elf")

    common.log("Creating a fake motd executable..")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(['chmod', '+x', masquerade])

    # Execute the fake motd executable
    common.log("Executing the fake motd executable..")
    commands = [
        masquerade,
        'chain',
        '-h',
        '8.8.8.8',
        '-p',
        '53',
        '-c',
        '/etc/update-motd.d/rta netcon -h 8.8.8.8 -p 53'
    ]
    common.execute([*commands], timeout=5, kill=True)

    # Cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
