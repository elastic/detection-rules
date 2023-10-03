# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="7fcf2f31-b510-45f8-9de4-7dc8f5ecb68b",
    platforms=["windows"],
    siem=[],
    endpoint=[{"rule_id": "d7bc9652-fe82-4fb3-8a48-4a9289c840f8", "rule_name": "Potential NTDLL Memory Unhooking"}, 
              {"rule_id": "2c4f5a78-a64f-4fcf-ac52-bf91fd9b82c8", "rule_name": "Suspicious Image Load via LdrLoadDLL"}, 
              {"rule_id": "703343f1-095a-4a5a-9bf4-5338db06ecb8", "rule_name": "Process Creation from Modified NTDLL"}],
    techniques=["T1055"],
)

# testing PE that will first unhook ntdll txt section and load ws2_32.dll, create notepad.exe from unhooked ntdll then load psapi.dll via LdrLoadDll
# source code -https://gist.github.com/Samirbous/cee44dbd0254c28d4f57709d5c723aee
BIN = common.get_path("bin", "rta_unhook_ldrload.exe")

@common.requires_os(*metadata.platforms)

def main():
    if Path(BIN).is_file():
        print(f'[+] - File {BIN} will be executed')
        common.execute(BIN)
        # cleanup
        common.execute(["taskkill", "/f", "/im", "notepad.exe"])

if __name__ == "__main__":
    exit(main())
