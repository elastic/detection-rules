# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b88c08af-eee5-4683-a56a-36e91e6386d5",
    platforms=["macos", "linux"],
    endpoint=[
        {"rule_name": "Privilege Escalation Enumeration via LinPEAS", "rule_id": "92bb2a27-745b-4291-90a1-b7b654df1379"}
    ],
    siem=[],
    techniques=["T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/sed"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
    else:
        common.create_macos_masquerade(masquerade)

    common.log("Executing fake sed command for LinPEAS behavior.")
    common.execute([masquerade, "testImPoSSssSiBlEeetest"], timeout=5, kill=True, shell=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
