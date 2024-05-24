# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="bc660bdd-9270-48dd-a956-5485d222a661",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Python Network Connection Followed by Command Execution",
            "rule_id": "b86c5998-3068-43e8-bfb5-ecb593e34ca9"
        }
    ],
    techniques=["T1071", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Creating a fake Python executable..")
    masquerade = "/dev/shm/python"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(['chmod', '+x', masquerade])

    commands = [masquerade, 'chain', '-h', '8.8.8.8', '-p', '53', '-c', 'whoami']
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    exit(main())
