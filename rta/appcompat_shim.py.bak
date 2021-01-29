# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Application Compatibility Shims
# RTA: appcompat_shim.py
# ATT&CK: T1138
# Description: Use sdbinst.exe to install a binary patch/application shim.

import time

from . import common

SHIM_FILE = common.get_path("bin", "CVE-2013-3893.sdb")


@common.requires_os(common.WINDOWS)
@common.dependencies(SHIM_FILE)
def main():
    common.log("Application Compatibility Shims")

    common.execute(["sdbinst.exe", "-q", "-p", SHIM_FILE])
    time.sleep(2)

    common.log("Removing installed shim", log_type="-")
    common.execute(["sdbinst.exe", "-u", SHIM_FILE])


if __name__ == "__main__":
    exit(main())
