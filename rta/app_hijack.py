# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9e87748e-9866-4b6b-832d-5cba4dda14e8",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Potential Default Application Hijacking",
            "rule_id": "5d2c3833-a36a-483a-acea-5bf8cf363a81",
        }
    ],
    siem=[],
    techniques=["T1574"],
)


@common.requires_os(*metadata.platforms)
def main():

    app_dir = Path("/Applications/test/Contents/")
    app_dir.mkdir(parents=True, exist_ok=True)
    masquerade = str(app_dir / "hijack")
    common.create_macos_masquerade(masquerade)
    masquerade2 = "/tmp/open"
    common.create_macos_masquerade(masquerade2)

    # Execute command
    common.log("Launching fake open commands to mimic hijacking applications")
    command = f"{masquerade2} -a /System/Applications/*"
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True)

    # cleanup
    common.remove_directory(str(app_dir))
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
