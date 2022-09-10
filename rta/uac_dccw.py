# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="cfb116f0-ad83-4d77-803f-064c2cfd93fe",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Parent-Child Relationship", "rule_id": "18a26e3e-e535-4d23-8ffa-a3cdba56d16e"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "UAC Bypass Attempt via DCCW DLL Search Order Hijacking",
            "rule_id": "093bd845-b59f-4868-a7dd-62d48b737bf6",
        },
    ],
    siem=[],
    techniques=["T1129", "T1548", "T1036", "T1055", "T1574"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    dccw = "C:\\Users\\Public\\dccw.exe"
    dllhost = "C:\\Users\\Public\\dllhost.exe"
    dccwpath = "C:\\Users\\Public\\dccw.exe.test"
    dccwpathdll = "C:\\Users\\Public\\dccw.exe.test\\a.dll"
    dccwpathdll2 = "C:\\Users\\Public\\dccw.exe.test\\b.dll"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, dccw)
    common.copy_file(EXE_FILE, dllhost)

    # Create Dir
    common.execute([powershell, "/c", f"New-Item -Path {dccwpath} -Type Directory"], timeout=10)
    common.copy_file(EXE_FILE, dccwpathdll)
    common.execute([dllhost, "/c", f"Rename-Item {dccwpathdll} {dccwpathdll2}"], timeout=10)
    common.execute([dccw, "/c", powershell], timeout=2, kill=True)
    common.remove_files(dccw, dllhost, dccwpathdll2)
    common.execute([powershell, "/c", f"rmdir {dccwpath} -Force"], timeout=3)


if __name__ == "__main__":
    exit(main())
