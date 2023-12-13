# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="7ab3930d-f38c-44d3-bb9d-32c0846caad9",
    platforms=["linux"],
    endpoint=[{"rule_name": "Fake Detected via cat", "rule_id": "7e43f49a-bee1-4c94-9744-99458aa73f95"}],
    siem=[],
    techniques=[""],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Creating a fake cat executable..")
    masquerade = "/tmp/cat"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)

    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "netcon", "-h", "127.0.0.1", "-p", "1337"]

    common.log("Simulating cat network activity..")
    common.execute([*commands], timeout=5)
    common.log("Cat network simulation successful!")
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("RTA completed!")


if __name__ == "__main__":
    exit(main())
    