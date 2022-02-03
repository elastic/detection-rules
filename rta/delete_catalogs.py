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


@common.requires_os(common.WINDOWS)
def main():
    warning = "Deleting the backup catalog may have unexpected consequences. Operational issues are unknown."
    common.log("WARNING: %s" % warning, log_type="!")
    time.sleep(2.5)

    common.execute(["wbadmin", "delete", "catalog", "-quiet"])


if __name__ == "__main__":
    exit(main())
