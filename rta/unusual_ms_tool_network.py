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
from . import RtaMetadata

if sys.version_info > (3,):
    urlliblib = "urllib.request"
else:
    urlliblib = "urllib"


metadata = RtaMetadata(
    uuid="cf94f5cc-5265-4287-80e5-82d9663ecf2e",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            "rule_id": "1fe3b299-fbb5-4657-a937-1d746f2c711a",
            "rule_name": "Unusual Network Activity from a Windows System Binary",
        },
        {"rule_id": "610949a1-312f-4e04-bb55-3a79b8c95267", "rule_name": "Unusual Process Network Connection"},
    ],
    techniques=["T1127"],
)


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
    "odbcconf.exe",
]


def http_from_process(name, ip, port):
    path = os.path.join(common.BASE_DIR, name)
    common.log("Making HTTP GET from %s" % path)
    shutil.copy(sys.executable, path)
    common.execute(
        [
            path,
            "-c",
            "from %s import urlopen ; urlopen('http://%s:%d')" % (urlliblib, ip, port),
        ]
    )
    common.remove_file(path)


@common.requires_os(metadata.platforms)
def main():
    server, ip, port = common.serve_web()

    for process in process_names:
        http_from_process(process, ip, port)

    server.shutdown()


if __name__ == "__main__":
    exit(main())
