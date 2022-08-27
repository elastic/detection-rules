# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: COM Hijack via Script Object
# RTA: scrobj_com_hijack.py
# ATT&CK: T1122
# Description: Modifies the Registry to create a new user-defined COM broker, "scrobj.dll".

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_id": "16a52c14-7883-47af-8745-9357803f0d4c",
            "rule_name": "Component Object Model Hijacking",
        }
    ],
    "ENDPOINT": [],
}
TACTICS = ["TA0003"]
RTA_ID = "ac739578-c978-429f-9454-0bbe82f993f4"


@common.requires_os(PLATFORMS)
def main():
    key = "SOFTWARE\\Classes\\CLSID\\{00000000-0000-0000-0000-0000DEADBEEF}"
    subkey = "InprocServer32"
    value = ""
    scrobj = "C:\\WINDOWS\\system32\\scrobj.dll"
    key_path = key + "\\" + subkey

    with common.temporary_reg(common.HKCU, key_path, value, scrobj, pause=True):
        pass


if __name__ == "__main__":
    exit(main())
