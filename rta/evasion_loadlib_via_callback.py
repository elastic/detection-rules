# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="ae4b2807-3a16-485e-bb69-5d36bbe9b7d1",
    platforms=["windows"],
    siem=[],
    endpoint=[{"rule_id": "fae9f554-d3bc-4d48-8863-54d0dd68db54", "rule_name": "Library Loaded via a CallBack Function"}],
    techniques=["T1574"],
)

# testing PE that will load ws2_32 and dnsapi.dll via a Callback function using RtlQueueWorkItem and RtlRegisterWait
# source code - https://gist.github.com/joe-desimone/0b2bb00eca4c522ba0bd5541a6f3528b
BIN = common.get_path("bin", "LoadLib-Callback64.exe")

@common.requires_os(*metadata.platforms)

def main():
    if Path(BIN).is_file():
        print(f'[+] - File {BIN} will be executed')
        common.execute(BIN)
        # cleanup
        common.execute(["taskkill", "/f", "/im", "LoadLib-Callback64.exe"])
        print(f'[+] - RTA Done!')

if __name__ == "__main__":
    exit(main())
