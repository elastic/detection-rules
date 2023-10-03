# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="fa2bbba7-66f4-4fd6-9c81-599d58fe67e8",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Background Process Execution via Shell", "rule_id": "603ac59e-9cca-4c48-9750-e38399079043"}
    ],
    siem=[],
    techniques=["T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/sh"
    common.create_macos_masquerade(masquerade)

    common.log("Executing background processes via sh from tmp directory.")
    command = 'bash -c "/* &"'
    common.execute([masquerade, "childprocess", command], shell=True, timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
