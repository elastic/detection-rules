# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="5b9be46b-18f2-4b74-9003-36d763c5d887",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Scheduled Job Executing Binary in Unusual Location",
            "rule_id": "f2a52d42-2410-468b-9910-26823c6ef822"
        }
    ],
    techniques=["T1543", "T1053", "T1543"],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Creating a fake cron executable..")
    masquerade = "/tmp/cron"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(['chmod', '+x', masquerade])

    commands = [masquerade, 'exec', '-c', '/dev/shm/foo']
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    exit(main())
