# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: WinRAR Startup Folder
# RTA: winrar_startup_folder.py
# ATT&CK: T1060
# Description: Writes batch file into Windows Startup folder using process ancestry tied to exploit (CVE-2018-20250)

import os

from . import common
from . import RtaMetadata


metadata = RtaMetadata(uuid="6d2d3c21-2d71-4395-8ab7-b1d0138d9225", platforms=["windows"], endpoint=[], siem=[], techniques=[])


@common.requires_os(metadata.platforms)
def main():
    common.log("WinRAR StartUp Folder Persistence")
    win_rar_path = os.path.abspath("WinRAR.exe")
    ace_loader_path = os.path.abspath("Ace32Loader.exe")
    batch_file_path = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\mssconf.bat"
    startup_path = os.environ["USERPROFILE"] + batch_file_path
    common.copy_file("C:\\Windows\\System32\\cmd.exe", win_rar_path)
    common.copy_file("C:\\Windows\\System32\\cmd.exe", ace_loader_path)
    common.execute(
        [win_rar_path, "/c", ace_loader_path, "/c", "echo", "test", "^>", startup_path],
        kill=True,
    )
    common.remove_file(startup_path)
    common.remove_file(ace_loader_path)
    common.remove_file(win_rar_path)


if __name__ == "__main__":
    exit(main())
