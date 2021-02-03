# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Export Registry Hives
# RTA: registry_hive_export.py
# ATT&CK: TBD
# Description: Exports the SAM, SECURITY and SYSTEM hives - useful in credential harvesting and discovery attacks.

import os

from . import common

REG = "reg.exe"


@common.requires_os(common.WINDOWS)
def main():
    for hive in ["sam", "security", "system"]:
        filename = os.path.abspath("%s.reg" % hive)
        common.log("Exporting %s hive to %s" % (hive, filename))
        common.execute([REG, "save", "hkey_local_machine\\%s" % hive, filename])
        common.remove_file(filename)

        common.execute([REG, "save", "hklm\\%s" % hive, filename])
        common.remove_file(filename)


if __name__ == "__main__":
    exit(main())
