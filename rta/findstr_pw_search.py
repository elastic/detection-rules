# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Recursive Password Search
# RTA: findstr_pw_search.py
# ATT&CK: T1081
# Description: Recursively searches files looking for the string "password".

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {"SIEM": [], "ENDPOINT": []}
TACTICS = []
RTA_ID = "332d6bb9-845f-401d-af5a-368f1f10e27a"


@common.requires_os(PLATFORMS)
def main():
    path = "c:\\rta"
    common.log("Searching for passwords on %s" % path)
    common.execute(
        ["dir", path, "/s", "/b", "|", "findstr", "password"], shell=True, timeout=15
    )


if __name__ == "__main__":
    exit(main())
