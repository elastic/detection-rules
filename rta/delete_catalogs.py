# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Catalog Deletion with wbadmin.exe
# RTA: delete_catalogs.py
# ATT&CK: T1107
# Description: Uses wbadmin to delete the backup catalog.

import time

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="8ffd2053-c04a-435a-84b3-a8403a5395db",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "581add16-df76-42bb-af8e-c979bfb39a59", "rule_name": "Deleting Backup Catalogs with Wbadmin"}],
    techniques=["T1490"],
)


@common.requires_os(metadata.platforms)
def main():
    warning = "Deleting the backup catalog may have unexpected consequences. Operational issues are unknown."
    common.log("WARNING: %s" % warning, log_type="!")
    time.sleep(2.5)

    common.execute(["wbadmin", "delete", "catalog", "-quiet"])


if __name__ == "__main__":
    exit(main())
