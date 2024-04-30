# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


from . import common
from . import RtaMetadata



metadata = RtaMetadata(
    uuid="bdb54776-d643-4f4c-90cc-7719c2fa7eab",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Sensitive File Access - Unattended Panther", "rule_id": "52e4ad92-e09b-4331-b827-cd0f2cbaf576"},
        {"rule_name": "Potential Discovery of Windows Credential Manager Store", "rule_id": "cc60be0e-2c6c-4dc9-9902-e97103ff8df9"},
        {"rule_name": "Potential Discovery of DPAPI Master Keys", "rule_id": "84bbe951-5141-4eb3-b9cf-8dfeea62a94e"},
        {"rule_name": "Suspicious Access to Active Directory Database File", "rule_id": "d66765b8-010b-4a40-ab62-1d8f13a44878"},
        {"rule_name": "Sensitive File Access - SSH Saved Keys", "rule_id": "1487d726-2bd2-4a9e-a9d2-db8aef1d6239"},
        {"rule_name": "Failed Attempts to Access Sensitive Files", "rule_id": "3163dd96-c677-4f1f-98bf-c8f3c81b197b"},
        {"rule_name": "Sensitive File Access - System Admin Utilities", "rule_id": "949c72ee-a283-4673-afe0-7fa72bddc2f6"},
        {"rule_name": "Potential Credential Access via Windows Credential History", "rule_id": "ce8a6302-7248-457a-8427-3d6bad14e2f0"},
    ],    
    siem=[],
    techniques=["T1555.004", "T1552.001", "T1003.003"],
)

@common.requires_os(*metadata.platforms)


def main():
    from os import path
    import win32file
    files = ["%localappdata%\\Google\\Chrome\\User Data\\Default\\Login Data",
             "%localappdata%\\Google\\Chrome\\User Data\\Default\\History",
             "%localappdata%\\Google\\Chrome\\User Data\\Default\\Local State",
             "%appdata%\\Mozilla\\Firefox\\Profiles\\test\\logins.json",
             "%appdata%\\Mozilla\\Firefox\\Profiles\\test\\cookies.sqlite",
             "%appdata%\\key3.db",
             "%appdata%\\KeePass\\KeePass.config.xml",
             "C:\\Users\\Public\\AppData\\Local\\Microsoft\\Vault\\test",
             "%appdata%\\Microsoft\\Credentials\\test",
             "C:\\Windows\\Panther\\Unattend.xml",
             "C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\test",
             "C:\\Windows\\NTDS\\NTDS.dit",
             "C:\\Users\\Public\\.ssh\\known_hosts",
             "C:\\Users\\Public\\AppData\\Something\\FileZilla\\recentservers.xml",
             "%appdata%\\Microsoft\\Protect\\CREDHIST"]
    for item in files:
        try:
            win32file.CreateFile(path.expandvars(item), win32file.GENERIC_READ, 0, None, 3, 0, None)
            time.sleep(2)
        except Exception as e:
               print(f'[x] - Failed to open {item}')
               pass
         
if __name__ == "__main__":
    exit(main())
