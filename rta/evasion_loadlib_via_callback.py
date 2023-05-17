# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os

metadata = RtaMetadata(
    uuid="ae4b2807-3a16-485e-bb69-5d36bbe9b7d1",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "fae9f554-d3bc-4d48-8863-54d0dd68db54", "rule_name": "Library Loaded via a CallBack Function"}],
    techniques=["T1574"],
)

# testing PE that will load ws2_32 and dnsapi.dll via a Callback function using RtlQueueWorkItem and RtlRegisterWait
BIN = common.get_path("bin", "LoadLib-Callback64.exe")

@common.requires_os(metadata.platforms)

def main():
    if os.path.exists(BIN) :
        print('[+] - File ', BIN, 'will be executed')
        common.execute(BIN)
        # cleanup
        common.execute(["taskkill", "/f", "/im", "LoadLib-Callback64.exe"])
        print('[+] - RTA Done!')

if __name__ == "__main__":
    exit(main())
