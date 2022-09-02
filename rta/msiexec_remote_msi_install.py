# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="8cb1d15d-d945-4f1c-9238-b221600156bc",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {"rule_name": "Remote MSI Package Installation via MSIEXEC", "rule_id": "706bf4ca-45b7-4eb1-acae-b1228124594a"},
    ],
    siem=[],
    techniques=["T1218", "T1036"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    msiexec = "C:\\Users\\Public\\msiexec.exe"
    common.copy_file(EXE_FILE, msiexec)

    set_reg_cmd = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE' -Name 'InstallSource' -Value http://google.com"
    rem_reg_cmd = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE' -Name 'InstallSource'"

    # Execute command
    common.log("Creating reg key using fake msiexec")
    common.execute([msiexec, "/c", set_reg_cmd, "; cmd.exe", "/V"], timeout=5, kill=True)
    common.execute([msiexec, "/c", rem_reg_cmd], timeout=5, kill=True)
    common.remove_file(msiexec)


if __name__ == "__main__":
    exit(main())
