# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="fd5fb7a8-398a-4322-ae28-8f88cce6aa88",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Interactive Shell Spawned via Hidden Process",
            "rule_id": "52deef30-e633-49e1-9dd2-da1ad6cb5e43"
        }
    ],
    techniques=["T1059", "T1564"],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Creating a fake hidden executable..")
    masquerade = "/tmp/.evil"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(['chmod', '+x', masquerade])

    commands = [masquerade, 'exec', '-c', '-i']
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    exit(main())
