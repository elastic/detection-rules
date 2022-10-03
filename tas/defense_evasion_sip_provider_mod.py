# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d765973d-bfbc-4f1f-bb5b-2a1fb66ddb31",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'f2c7b914-eda3-40c2-96ac-d23ef91776ca', 'rule_name': 'SIP Provider Modification'}],
    techniques=[""],
)


@common.requires_os(metadata.platforms)
def main():
    key = ("SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\"
           "CryptSIPDllPutSignedDataMsg\\{603BCC1F-4B59-4E08-B724-D2C6297EF351}")
    value = "Dll"
    data = "test.dll"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
