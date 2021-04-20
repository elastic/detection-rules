# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Unexpected Network Activity from Microsoft Tools
# RTA: unusual_ms_tool_network.py
# ATT&CK: T1127
# Description: Creates network traffic from a process which is named to match common administration and developer tools
#              that do not typically make network traffic unless being used maliciously.

import os
import shutil
import sys

from . import common

if sys.version_info > (3,):
    urlliblib = "urllib.request"
else:
    urlliblib = "urllib"

process_names = [
    "bginfo.exe",
    "msdt.exe",
    "ieexec.exe",
    "cdb.exe",
    "dnx.exe",
    "rcsi.exe",
    "csi.exe",
    "cmstp.exe",
    "xwizard.exe",
    "fsi.exe",
    "odbcconf.exe"
]


def http_from_process(name, ip, port):
    path = os.path.join(common.BASE_DIR, name)
    common.log("Making HTTP GET from %s" % path)
    shutil.copy(sys.executable, path)
    common.execute([path, "-c", "from %s import urlopen ; urlopen('http://%s:%d')" % (urlliblib, ip, port)])
    common.remove_file(path)


@common.requires_os(common.WINDOWS)
def main():
    server, ip, port = common.serve_web()

    for process in process_names:
        http_from_process(process, ip, port)

    server.shutdown()


if __name__ == "__main__":
    exit(main())
