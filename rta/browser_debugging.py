# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import platform

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e061a96e-4c31-4f67-9745-6ff873f7829e",
    platforms=["windows", "macos", "linux"],
    endpoint=[
        {
            "rule_name": "Potential Cookies Theft via Browser Debugging",
            "rule_id": "5d7328aa-973b-41e7-a6b3-6f40ea3094f1",
        }
    ],
    siem=[
        {
            "rule_name": "Potential Cookies Theft via Browser Debugging",
            "rule_id": "027ff9ea-85e7-42e3-99d2-bbb7069e02eb",
        }
    ],
    techniques=["T1539"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    param1 = "--remote-debugging-port=9222"
    param2 = "--user-data-dir=remote-profile"
    if platform.system() == "Darwin":
        if platform.processor() == "arm":
            name = "com.apple.ditto_and_spawn_arm"
        else:
            name = "com.apple.ditto_and_spawn_intel"

        source = common.get_path("bin", name)
        chrome = "/tmp/google-chrome"
        common.copy_file(source, chrome)

        common.log("Starting browser on debug mode")
        common.execute([chrome, param1, param2], timeout=10, kill=True)

    elif common.CURRENT_OS == "linux":
        name = "linux.ditto_and_spawn"
        source = common.get_path("bin", name)
        chrome = "/tmp/google-chrome"
        common.copy_file(source, chrome)

        common.log("Starting browser on debug mode")
        common.execute([chrome, param1, param2], timeout=10, kill=True)
    else:
        chrome = "C:\\Users\\Public\\chrome.exe"
        common.copy_file(EXE_FILE, chrome)

        # Execute command
        common.log("Mimicking the start of a browser on debug mode")
        common.execute([chrome, "/c", "echo", param1, param2], timeout=10)
        common.remove_file(chrome)


if __name__ == "__main__":
    exit(main())
