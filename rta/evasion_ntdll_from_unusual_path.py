# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


from . import common
from . import RtaMetadata
import win32file, win32api, os

metadata = RtaMetadata(
    uuid="e6d5315f-4c70-4788-8564-e7c23786a4d0",
    platforms=["windows"],
    endpoint=[{"rule_name": "NTDLL Loaded from an Unusual Path", "rule_id": "3205274e-7eb0-4765-a712-5783361091ae"}],    
    siem=[],
    techniques=["T1055"],
)

@common.requires_os(metadata.platforms)


def main(): 
    win32file.CopyFile("c:\\windows\\system32\\ntdll.dll", "c:\\users\\public\\notntdll.dll", 0) 
    if os.path.exists("c:\\users\\public\\notntdll.dll"): 
       print("[+] - NTDLL copied") 
       r = win32api.LoadLibrary("c:\\users\\public\\notntdll.dll") 
       if r > 0 : 
          print("[+] - NTDLL copy loaded") 
       else :  
          print('[+] - Failed to load ntdll')
         
if __name__ == "__main__":
    exit(main())