# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Mac Descendant of an Office Application
# RTA: mac_office_descendant.py
# Description: Creates a suspicious process spawned from "Microsoft Word"

import os

from . import common
from . import RtaMetadata


metadata = RtaMetadata(uuid="bb523eb1-db67-4ae6-9369-af1a93322817", platforms=["macos"], endpoint=[], siem=[], techniques=[])


@common.requires_os(metadata.platforms)
def main():
    common.log("Emulating Microsoft Word running enumeration commands")
    office_path = os.path.abspath("Microsoft Word")
    common.copy_file("/bin/sh", office_path)

    common.execute([office_path], stdin="whoami")

    common.remove_files(office_path)


if __name__ == "__main__":
    exit(main())
