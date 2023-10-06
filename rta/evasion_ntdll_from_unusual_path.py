# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="e6d5315f-4c70-4788-8564-e7c23786a4d0",
    platforms=["windows"],
    endpoint=[{"rule_name": "NTDLL Loaded from an Unusual Path", "rule_id": "3205274e-7eb0-4765-a712-5783361091ae"}],    
    siem=[],
    techniques=["T1055"],
)



@common.requires_os(*metadata.platforms)
def main():
    import time
    from os import path

    import win32api
    import win32file
    win32file.CopyFile(path.expandvars("%systemroot%\\system32\\ntdll.dll"), path.expandvars("%localappdata%\\Temp\\notntdll.dll"), 0) 
    if Path(path.expandvars("%localappdata%\\Temp\\notntdll.dll")).is_file():
       print(f"[+] - NTDLL copied")
       r = win32api.LoadLibrary(path.expandvars("%localappdata%\\Temp\\notntdll.dll")) 
       if r > 0 : 
          print(f"[+] - NTDLL copy loaded")
          time.sleep(1)
          win32api.FreeLibrary(r)
          win32file.DeleteFile(path.expandvars("%localappdata%\\Temp\\notntdll.dll"))
          print(f'[+] - NTDLL copy deleted')
       else :  
          print('f[+] - Failed to load ntdll')
         
if __name__ == "__main__":
    exit(main())
    
