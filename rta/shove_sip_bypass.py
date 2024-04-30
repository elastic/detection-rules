# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1796555f-921a-459f-9661-0d94cf90fe81",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Potential SIP Bypass via the ShoveService", "rule_id": "7dea8cfc-92db-4081-9a5d-85ead8cedd5f"}
    ],
    siem=[],
    techniques=["T1068"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/sh"
    common.create_macos_masquerade(masquerade)

    common.log("Executing shove processes to mimic sip bypass.")
    command = "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/shove -x"
    common.execute([masquerade, "childprocess", command], shell=True, timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
