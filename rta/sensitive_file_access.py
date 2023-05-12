# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


from . import common
from . import RtaMetadata
from os import path
import win32file
import win32.lib.win32con as win32con

metadata = RtaMetadata(
    uuid="bdb54776-d643-4f4c-90cc-7719c2fa7eab",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Sensitive File Access - Unattended Panther", "rule_id": "52e4ad92-e09b-4331-b827-cd0f2cbaf576"},
        {"rule_name": "Potential Discovery of Windows Credential Manager Store", "rule_id": "cc60be0e-2c6c-4dc9-9902-e97103ff8df9"},
        {"rule_name": "Potential Discovery of DPAPI Master Keys", "rule_id": "84bbe951-5141-4eb3-b9cf-8dfeea62a94e"},
    ],    
    siem=[],
    techniques=["T1134"],
)

@common.requires_os(metadata.platforms)


def main():
    files = ["%localappdata%\\Google\\Chrome\\User Data\\Default\\Login Data",
             "%localappdata%\\Google\\Chrome\\User Data\\Default\\History",
             "%localappdata%\\Google\\Chrome\\User Data\\Default\\Local State",
             "%appdata%\\Mozilla\\Firefox\\Profiles\\test\\logins.json",
             "%appdata%\\Mozilla\\Firefox\\Profiles\\test\\cookies.sqlite",
             "%appdata%\\key3.db",
             "C:\\Users\\Public\\AppData\\Local\\Microsoft\\Vault\\test",
             "%appdata%\\Microsoft\\Credentials\\test",
             "C:\\Windows\\Panther\\Unattend.xml",
             "C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\test"]
    for f in files:
        try:
            win32file.CreateFile(path.expandvars(f), win32file.GENERIC_READ, 0, None, win32con.OPEN_EXISTING, 0, None)
            time.sleep(2)
        except Exception as e:
               print('failed to open ', f)
               pass
         
if __name__ == "__main__":
    exit(main())