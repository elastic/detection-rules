# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Recursive Password Search
# RTA: findstr_pw_search.py
# ATT&CK: T1081
# Description: Recursively searches files looking for the string "password".

from . import common


@common.requires_os(common.WINDOWS)
def main():
    path = "c:\\rta"
    common.log("Searching for passwords on %s" % path)
    common.execute(["dir", path, "/s", "/b", "|", "findstr", "password"], shell=True, timeout=15)


if __name__ == "__main__":
    exit(main())
