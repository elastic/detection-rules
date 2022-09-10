# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4e63cb99-b56d-4c75-9cda-3a7f30861d35",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Persistence via Folder Action Script", "rule_id": "c292fa52-4115-408a-b897-e14f684b3cb7"}],
    techniques=["T1037", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/com.apple.foundation.UserScriptService"
    masquerade2 = "/tmp/osascript"
    common.create_macos_masquerade(masquerade)
    common.create_macos_masquerade(masquerade2)

    # Execute command
    common.log("Launching fake commands to mimic modification of a Folder Action script")
    common.execute([masquerade, "childprocess", masquerade2], timeout=1, kill=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
