# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="214db941-51ba-4867-b9bf-9b22ff07eea8",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {"rule_name": "Finder Sync Plugin Registered and Enabled", "rule_id": "37f638ea-909d-4f94-9248-edd21e4a9906"}
    ],
    techniques=["T1543"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/pluginkit"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake commands to miic finder sync plugins.")
    common.execute([masquerade, "-a"], timeout=1, kill=True)
    common.execute([masquerade, "-e", "use", "-i"], timeout=1, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
