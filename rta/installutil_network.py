# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Network Traffic from InstallUtil
# RTA: installutil_network.py
# ATT&CK: T1118
# Elastic detection: InstallUtil Process Making Network Connections
# Elastic detection: Unusual Network Activity from a Windows System Binary
# Description: Uses mock .NET malware and InstallUtil to create network activity from InstallUtil.

import os
import sys

from . import common

MY_DOT_NET = common.get_path("bin", "mydotnet.exe")


@common.requires_os(common.WINDOWS)
@common.dependencies(MY_DOT_NET)
def main():
    server, ip, port = common.serve_web()
    common.clear_web_cache()

    target_app = "mydotnet.exe"
    common.patch_file(MY_DOT_NET, common.wchar(":8000"), common.wchar(":%d" % port), target_file=target_app)

    install_util64 = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe"
    install_util86 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe"
    fallback = False

    if os.path.exists(install_util64):
        install_util = install_util64
    elif os.path.exists(install_util86):
        install_util = install_util86
    else:
        install_util = None
        fallback = True

    if not fallback:
        common.clear_web_cache()
        common.execute([install_util, '/logfile=', '/LogToConsole=False', '/U', target_app])

    else:
        common.log("Unable to find InstallUtil, creating temp file")
        install_util = os.path.abspath("InstallUtil.exe")
        common.copy_file(sys.executable, install_util)
        common.execute([install_util, "-c", "import urllib; urllib.urlopen('http://%s:%d')" % (common.get_ip(), port)])
        common.remove_file(install_util)

    common.remove_file(target_app)
    server.shutdown()


if __name__ == "__main__":
    exit(main())
