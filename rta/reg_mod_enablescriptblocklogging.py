# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="5ef57ec6-32a0-40b2-b9a7-c4eda4cd3e49",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '818e23e6-2094-4f0e-8c01-22d30f3506c6', 'rule_name': 'PowerShell Script Block Logging Disabled'}],
    techniques=['T1562', 'T1562.002'],
)


@common.requires_os(*metadata.platforms)
def main():
    key = "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
    value = "EnableScriptBlockLogging"
    data = 0

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass


if __name__ == "__main__":
    exit(main())
