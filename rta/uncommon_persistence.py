# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Uncommon Registry Persistence Change
# RTA: uncommon_persistence.py
# ATT&CK: T1112
# Description: Modifies the Registry for Logon Shell persistence using a mock payload.

import sys

from . import common

# There are many unconventional ways to leverage the Registry for persistence:

'''
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce\\*" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\IconServiceLib" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AppSetup" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\VmApplet" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell" or
key_path == "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff\\Script" or
key_path == "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon\\Script" or
key_path == "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown\\Script" or
key_path == "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup\\Script" or
key_path == "*\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\*\\ShellComponent" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnConnect\\MicrosoftActiveSync" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnDisconnect\\MicrosoftActiveSync" or
key_path == "*\\SOFTWARE\\Microsoft\\Ctf\\LangBarAddin\\*\\FilePath" or
key_path == "*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Exec" or
key_path == "*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Script" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\*" or
key_path == "*\\SOFTWARE\\Microsoft\\Command Processor\\Autorun" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\VerifierDlls" or
key_path == "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GpExtensions\\*\\DllName" or
key_path == "*\\SOFTWARE\\Microsoft\\Office Test\\Special\\Perf\\" or
(key_path == "*\\System\\ControlSet*\\Control\\SafeBoot\\AlternateShell" and bytes_written_string != "cmd.exe") or
key_path == "*\\System\\ControlSet*\\Control\\Terminal Server\\Wds\\rdpwd\\StartupPrograms" or
key_path == "*\\System\\ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram" or
key_path == "*\\System\\ControlSet*\\Control\\Session Manager\\BootExecute" or
key_path == "*\\System\\ControlSet*\\Control\\Session Manager\\SetupExecute" or
key_path == "*\\System\\ControlSet*\\Control\\Session Manager\\Execute" or
key_path == "*\\System\\ControlSet*\\Control\\Session Manager\\S0InitialCommand" or
key_path == "*\\System\\ControlSet*\\Control\\ServiceControlManagerExtension" or
key_path == "*\\System\\ControlSet*\\Control\\Session Manager\\AppCertDlls\\*" or
key_path == "*\\System\\ControlSet*\\Control\\BootVerificationProgram\\ImagePath" or
key_path == "*\\System\\Setup\\CmdLine"
)
'''  # noqa: E501


@common.requires_os(common.WINDOWS)
def main(target="calc.exe"):
    winreg = common.get_winreg()
    hkey = winreg.CreateKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")

    common.log("Setting reg key")
    winreg.SetValueEx(hkey, "Userinit", 0, winreg.REG_SZ, target)

    common.log("Setting reg key", log_type="-")
    winreg.DeleteValue(hkey, "Userinit")
    winreg.CloseKey(hkey)


if __name__ == "__main__":
    exit(main(*sys.argv[:1]))
