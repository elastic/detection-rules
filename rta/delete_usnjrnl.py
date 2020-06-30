# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: USN Journal Deletion with fsutil.exe
# RTA: delete_usnjrnl.py
# ATT&CK: T1107
# Description: Uses fsutil to delete the USN journal.

import time

from . import common


@common.requires_os(common.WINDOWS)
def main():
    message = "Deleting the USN journal may have unintended consequences"
    common.log("WARNING: %s" % message, log_type="!")
    time.sleep(2.5)
    common.execute(["fsutil", "usn", "deletejournal", "/d", "C:"])


if __name__ == "__main__":
    exit(main())
