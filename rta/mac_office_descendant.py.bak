# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Mac Descendant of an Office Application
# RTA: mac_office_descendant.py
# Description: Creates a suspicious process spawned from "Microsoft Word"

import os

from . import common


@common.requires_os(common.MACOS)
def main():
    common.log("Emulating Microsoft Word running enumeration commands")
    office_path = os.path.abspath("Microsoft Word")
    common.copy_file("/bin/sh", office_path)

    common.execute([office_path], stdin="whoami")

    common.remove_files(office_path)


if __name__ == "__main__":
    exit(main())
