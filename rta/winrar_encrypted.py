# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Encrypting files with WinRAR
# RTA: winrar_encrypted.py
# ATT&CK: T1022
# Description: Uses "bin\rar.exe" to perform encryption of archives and archive headers.

import base64
import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="6d2d3c21-2d71-4395-8ab7-b1d0138d9225",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "45d273fb-1dca-457d-9855-bcb302180c21", "rule_name": "Encrypting Files with WinRar or 7z"}],
    techniques=["T1560"],
)


MY_APP = common.get_path("bin", "myapp.exe")
WINRAR = common.get_path("bin", "Rar.exe")


def create_exfil(path=Path("secret_stuff.txt").resolve()):
    common.log("Writing dummy exfil to %s" % path)
    with open(path, "wb") as f:
        f.write(base64.b64encode(b"This is really secret stuff" * 100))
    return path


@common.requires_os(*metadata.platforms)
@common.dependencies(MY_APP, WINRAR)
def main(password="s0l33t"):
    # Copies of the rar.exe for various tests
    winrar_bin_modsig = common.get_path("bin", "rar_broken-sig.exe")
    common.patch_file(WINRAR, b"win.rar GmbH", b"bad.bad GmbH", winrar_bin_modsig)

    # Renamed copies of executables
    winrar_bin_modsig_a = Path("a.exe").resolve()
    winrar_bin_b = Path("b.exe").resolve()

    common.copy_file(winrar_bin_modsig, winrar_bin_modsig_a)
    common.copy_file(WINRAR, winrar_bin_b)

    # Output options for various tests
    rar_file = Path("out.rar").resolve()
    rar_file_jpg = Path("out.jpg").resolve()
    common.remove_files(rar_file, rar_file_jpg)

    # use case: rar with -hp to generate new rar file w/ .rar

    common.log("Test case 1: Basic use new rar out", log_type="!")
    exfil = create_exfil()
    common.execute([WINRAR, "a", rar_file, "-hp" + password, exfil])

    # use case: rar with -hp to add to existing rar file
    # didn't delete rar from previous case
    common.log("Test case 2: Basic use add to existing rar", log_type="!")
    exfil2 = create_exfil("more_stuff.txt")
    common.execute([WINRAR, "a", rar_file, "-hp" + password, exfil2])
    common.remove_files(exfil2, rar_file)

    #  use case: process_name == "*rar*" - yes
    #            original_file_name == "*rar*" - no
    #            signature_signer == "*win.rar*" - no
    #            output filename == "*.rar" - no
    common.log("Test case 3: *rar* in process name", log_type="!")
    common.execute([winrar_bin_modsig, "a", rar_file_jpg, "-hp" + password, exfil])
    common.remove_files(rar_file_jpg)

    #  use case: process_name == "*rar*" - no
    #            original_file_name == "*rar*" - no
    #            signature_signer == "*win.rar*" - yes
    #            output filename == "*.rar" - no
    common.log("Test case 4: Expected WinRar signature", log_type="!")
    common.execute([winrar_bin_b, "a", rar_file_jpg, "-hp" + password, exfil])
    common.remove_files(rar_file_jpg)

    #  use case: process_name == "*rar*" - no
    #            original_file_name == "*rar*" - no
    #            signature_signer == "*win.rar*" -no
    #            output filename == "*.rar" - yes
    common.log("Test case 5: *.rar in output filename", log_type="!")
    common.execute([winrar_bin_modsig_a, "a", rar_file, "-hp" + password, exfil])

    common.remove_files(rar_file, winrar_bin_modsig_a, winrar_bin_b, exfil)

    #   false positive - should not match signature
    #   use case: process_name == "*rar*" - no
    #            original_file_name == "*rar*" - no
    #            signature_signer == "*win.rar*" -no
    #            output filename == "*.rar" - no
    common.log("Test case 6: FP, shouldn't alert, run with myapp.exe", log_type="!")
    common.execute([MY_APP, "-hpbadargument"])

    common.log("Cleanup", "-")
    common.remove_files(winrar_bin_modsig, winrar_bin_modsig_a, winrar_bin_b)


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
