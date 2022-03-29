# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious DLL Registration by Regsvr32
# RTA: suspicious_dll_registration_regsvr32.py
# ATT&CK: T1117
# Description: Pretends to register DLL without traditional DLL extension using RegSvr32

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Suspicious DLL Registration by Regsvr32")

    common.execute(["regsvr32.exe", "-s", "meow.txt"])


if __name__ == "__main__":
    exit(main())
