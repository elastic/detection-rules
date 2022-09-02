# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Shortcut File Suspicious Process
# RTA: shortcut_file_suspicious_process.py
# ATT&CK: T1023,T1204,T1193,T1192
# Description: Create a .lnk file using cmd.exe

from . import common
from . import RtaMetadata


metadata = RtaMetadata(uuid="755e88fd-1fe1-44c7-b5f0-688a39fec420", platforms=["windows"], endpoint=[], siem=[], techniques=[])


@common.requires_os(metadata.platforms)
def main():
    common.log("Writing dummy shortcut file")
    shortcut_path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\evil.lnk"
    common.execute(["cmd", "/c", "echo", "dummy_shortcut", ">", shortcut_path])

    common.log("Deleting dummy shortcut file")
    common.remove_file(shortcut_path)


if __name__ == "__main__":
    exit(main())
