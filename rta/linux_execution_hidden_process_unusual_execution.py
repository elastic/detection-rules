# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="50efd72e-147a-4f24-8c36-f8d1d69a9cfc",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Suspicious Execution via a Hidden Process",
            "rule_id": "c52891b5-8f83-4571-8e68-ea2601f46285"
        }
    ],
    techniques=["T1059", "T1564", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Creating a fake hidden executable..")
    masquerade = "/tmp/.evil"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(['chmod', '+x', masquerade])

    commands = [masquerade, 'exec', '-c', '/dev/tcp']
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    exit(main())
